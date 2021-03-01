# ca_extend

#### Table of Contents

1. [Overview](#overview)
1. [Description - What the module does and why it is useful](#description)
1. [Setup - The basics of getting started with this module](#setup)
1. [Usage - Configuration options and additional functionality](#usage)
1. [Reference - An under-the-hood peek at what the module is doing](#reference)
1. [Development - Guide for contributing to the module](#development)

## Overview

This module can extend a certificate authority (CA) that's about to expire or has already expired.

A Puppet CA certificate is only valid for a finite time (a new installation of PE 2019.x / Puppet 6.x will create a 15 year CA, while earlier versions will create a 5 year CA; and upgrading does not extend the CA.), after which it expires.
When a CA certificate expires, Puppet services will no longer accept any certificates signed by that CA, and your Puppet infrastructure will immediately stop working.

If your CA certificate is expiring soon (or it's already expired), you need to:

* Generate a new CA certificate using the existing CA keypair.
* Distribute the new CA certificate to agents.

This module can automate those tasks.

## Description

This module is composed of Plans and Tasks to extend the expiration date of the CA certificate in Puppet Enterprise (and Puppet Open Source) and distribute that CA certificate to agents.

Note that, with Puppet Open Source, if the CA certificate is only used by the Puppet CA and no other integrations, there is no further action to take after using the two Plans.
However, if it is used for other integrations (such as SSL encrypted PuppetDB traffic) then those integrations will need to have their copy of the CA certificate updated. 
If the CA certificate is stored in any keystores, those will also need to be updated.

The functionality of this module is composed into two Plans:

*  `ca_extend::extend_ca_cert`
    * Extend the CA certificate and configure the Master and any Compilers to use that extended certificate.
*  `ca_extend::upload_ca_cert`
    * Distribute the CA certificate to agents using any transport supported by Puppet Bolt, such as `ssh`, `winrm`, or `pcp`.

Regardless of whether the CA certificate is expired, the `extend_ca_cert` plan may be used to extend its expiration date in-place and configure the Master and any Compilers to use it.

After the CA certificate has been extended, there are two methods for distributing it to agents.

* Using the `ca_extend::upload_ca_cert` plan or another method to copy the CA certificate to agents.
* Manually deleting `ca.pem` on agents and letting them download that file as part of the next Puppet agent run. The agent will download that file only if it is absent, so it must be deleted to use this method.

There are also two complementary tasks to check the expiration date of the CA certificate or any agent certificates.

* `ca_extend::check_ca_expiry`
    * Checks if the CA certificate expires by a certain date. Defaults to three months from today.
* `ca_extend::check_agent_expiry`
    * Checks if any agent certificate expires by a certain date. Defaults to three months from today.
    
** If the CA certificate is expiring or expired, you must extend it as soon as possible. **

## Setup

This module requires [Puppet Bolt](https://puppet.com/docs/bolt/latest/bolt_installing.html) >= 1.21.0 on either on the Master or an agent.

The recommended procedure for installation this module is to use a [Bolt Puppetfile](https://puppet.com/docs/bolt/latest/installing_tasks_from_the_forge.html#task-8928).
When creating a [Bolt project](https://puppet.com/docs/bolt/latest/bolt_project_directories.html#embedded-project-directory), specify this module and `puppetlabs-stdlib` as dependencies and run `bolt install modules`.

For example, to install Bolt and the required modules on a Master running EL 7:

```bash
sudo rpm -Uvh https://yum.puppet.com/puppet-tools-release-el-7.noarch.rpm
sudo yum install puppet-bolt
```

If your primary Puppet server or workstation has internet access, the project can be initialized with the needed dependencies with the following:
```bash
mkdir ca_extend
cd !$

bolt project init expiry --modules puppetlabs-stdlib,puppetlabs-ca_extend
```

Otherwise, if your primary Puppet server or workstation operates behind a proxy, initialize the project without the `--modules` option
```bash
mkdir ca_extend
cd !$

bolt project init expiry
```

Then edit your `bolt-project.yaml` to use the proxy according to the [documentation](https://puppet.com/docs/bolt/latest/bolt_installing_modules.html#install-modules-using-a-proxy).  Next, add the module dependencies to `bolt-project.yaml`:

```
---
name: expiry
modules:
  - name: puppetlabs-stdlib
  - name: puppetlabs-ca_extend

```

Finally, install the modules.

```bash
bolt module install
```

See the "Usage" section for how to run the tasks and plans remotely or locally on the master.

### Dependencies

*  A [Puppet Bolt](https://puppet.com/docs/bolt/latest/bolt_installing.html) >= 1.21.0
*  [puppetlabs-stdlib](https://puppet.com/docs/bolt/latest/bolt_installing.html)
*  A `base64` binary on the Master which supports the `-w` flag
*  `bash` >= 4.0 on the master

### Configuration

#### Inventory

This module works best with a Bolt [inventory file](https://puppet.com/docs/bolt/latest/inventory_file.html) to allow for simultaneous uploads to \*nix and Windows agents.
See the Bolt documentation for how to configure an inventory file.
See the `REFERENCE.md` for a sample inventory file.

Alternatively, you can use an `ssh` config file if you will only use that transport to upload the CA certificate to agents.
Bolt defaults to using the `ssh` transport, which in turn will use `~/.ssh/config` for options such as `username` and `private-key`.

#### PuppetDB

A convenient way to specify targets for the `ca_extend::upload_ca_cert` plan is by connecting Bolt to [PuppetDB](https://puppet.com/docs/bolt/latest/bolt_connect_puppetdb.html), after which [--query](https://puppet.com/docs/bolt/latest/bolt_command_reference.html#command-options) can be used to specify targets.
See `REFERENCE.md` for an example.

#### PCP

Note that you cannot use the Bolt `pcp` transport if your CA certificate has already expired, as the PXP-Agent service itself depends upon a valid CA certificate.

### Usage

First, check the expiration of the Puppet agent certificate by running the following command as root on the Master:

```
/opt/puppetlabs/puppet/bin/openssl x509 -in "$(/opt/puppetlabs/bin/puppet config print hostcert)" -enddate -noout
```

If, and only if, the `notAfter` date printed has already passed, then the Master certificate has expired and must be cleaned up before the CA can be regenerated:

```bash
mkdir -p -m 0700 /var/puppetlabs/backups
(umask 0077 && tar czf "/var/puppetlabs/backups/ssl-$(date +'%Y%m%d%H%M%S')".tar.gz "$(puppet config print ssldir)")

find "$(puppet config print ssldir)" -name "$(puppet config print certname).pem" -delete
```

Once the expiration has been checked, the CA can be regenerated.

```bash
bolt plan run ca_extend::extend_ca_cert --targets <master_fqdn> compile_masters=<comma_separated_compile_master_fqdns> --run-as root
```

Note that if you are running `extend_ca_cert` locally on the Master, you can avoid potential Bolt transport issues by specifying `--targets local://$(hostname -f)`, e.g.

```
bolt plan run ca_extend::extend_ca_cert --targets local://$(hostname -f) --run-as root
```

(The `master` and (optional) `compile_masters` parameters are Bolt targets, not certificate data.)

```bash
bolt plan run ca_extend::upload_ca_cert cert=<path_to_cert> --targets <TargetSpec>
```

```bash
bolt task run ca_extend::check_ca_expiry --targets <TargetSpec>
```

```bash
bolt task run ca_extend::check_agent_expiry --targets <TargetSpec>
```

See `REFERENCE.md` for more detailed examples.

## Reference

Puppet's security is based on a PKI using X.509 certificates.

This module's `ca_extend::extend_ca_cert` plan creates a new self-signed CA certificate using the same keypair as the prior self-signed CA. The new CA has the same:

* Keypair.
* Subject.
* Issuer.
* X509v3 Subject Key Identifier (the fingerprint of the public key).

The new CA has a different:

* Authority Key Identifier (just the serial number, since it's self-signed).
* Validity period (the point of the whole exercise).
* Signature (since we changed the serial number and validity period).

Since Puppet's services (and other services that use Puppet's PKI) validate certificates by trusting a self-signed CA and comparing its public key to the Signatures and Authority Key Identifiers of the certificates it has issued,
it's possible to issue a new self-signed CA certificate based on a prior keypair without invalidating any certificates issued by the old CA.
Once you've done that, it's just a matter of delivering the new CA certificate to every participant in the PKI.

## Development

Puppet Labs modules on the Puppet Forge are open source projects, and community contributions are essential for keeping them great.
We can’t access the huge number of platforms and myriad of hardware, software, and deployment configurations that Puppet is intended to serve.
We want to keep it as easy as possible to contribute changes so that our modules work in your environment.
There are a few guidelines that we need contributors to follow so that we can have a chance of keeping on top of things.

For more information, see our [module contribution guide.](https://docs.puppetlabs.com/forge/contributing.html)
