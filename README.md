# ca_extend

#### Table of Contents

1. [Overview](#overview)
1. [Description - What the module does and why it is useful](#description)
1. [Setup - The basics of getting started with this module](#setup)
1. [Usage - Configuration options and additional functionality](#usage)
1. [Reference - An under-the-hood peek at what the module is doing](#reference)
1. [Development - Guide for contributing to the module](#How-to-Report-an-issue-or-contribute-to-the-module)

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
    * Extend the CA certificate and configure the primary Puppet server, Replica, Compilers, and Postgres nodes to use that extended certificate.
*  `ca_extend::upload_ca_cert`
    * Distribute the CA certificate to agents using transport supported by Puppet Bolt, such as `ssh` and `winrm`.

Regardless of whether the CA certificate is expired, the `extend_ca_cert` plan may be used to extend its expiration date in-place and configure the primary Puppet server and any Compilers to use it.

On a filesystem CA the certificates are re-issued by a Ruby helper (`files/extend_cert.rb`, run with the Ruby that ships with Puppet) rather than by `openssl ca`.
A re-issued certificate keeps its subject, key, serial, notBefore and every extension, including a pathlen constraint, the criticality of each extension and any custom extension.
Only the notAfter (and so the signature) changes; the authorityKeyIdentifier is rebuilt from the issuer, as the CA-DB re-issue (PE-48305) does: it names the issuer by DN and serial only if the old one did.
Because the serial is kept, an intermediate (or other signer) whose authorityKeyIdentifier names the root by serial still chains to the extended root.
A certificate that already expires no earlier than the new end date (for example a root that outlives it) is kept as it is, so that it does not block renewing the other certificate of the bundle (the helper's `--keep-if-sufficient`, which extend.sh always passes). A kept certificate must still verify under its issuer's key, and is not capped to its issuer's expiry; the issuer, key and range refusals below still apply to it.
The helper refuses an issuer certificate whose subject is not the certificate's issuer name, a signing key that does not match the issuer certificate, and a new notAfter that is not in the future, not later than the current one, more than 36500 days ahead, or later than the issuer's.

After the CA certificate has been extended, there are three methods for distributing it to agents:

1. Using the `ca_extend::upload_ca_cert` plan or another method to copy the CA certificate to agents.
1. Manually deleting `ca.pem` on agents and letting them download that file as part of the next Puppet agent run. The agent will download that file only if it is absent, so it must be deleted to use this method.
1. Using a Puppet file resource to manage `ca.pem`. _Note: This method is only possible if the CA certificate has not yet expired because Puppet communications depend upon a valid CA certificate._

There are also complementary tasks to check the expiration date of the CA certificate, agent certificates, and the CA CRL.

* `ca_extend::check_ca_expiry`
    * Checks if the CA certificate expires by a certain date. Defaults to three months from today.
* `ca_extend::check_agent_expiry`
    * Checks if any agent certificate expires by a certain date. Defaults to three months from today.
*  `ca_extend::check_crl_expiry`
    * Checks if the CA crl on the primary server has expired
*  `ca_extend::crl_truncate`
    * Will truncate and regenerate the CA CRL, this should only be run if the CRL is expired
  
** If the CA certificate is expiring or expired, you must extend it as soon as possible. **

## Setup

This module requires [Puppet Bolt](https://puppet.com/docs/bolt/latest/bolt_installing.html) >= 1.38.0 on either on the primary Puppet server or a workstation with connectivity to the primary.

The installation procedure will differ depending on the version of Bolt.  If possible, using Bolt >= 3.0.0 is recommended.  For example, this will install the latest Bolt version on EL 7.

```bash
sudo rpm -Uvh https://yum.puppet.com/puppet-tools-release-el-7.noarch.rpm
sudo yum install puppet-bolt
```

The following two sections show how to install the module dependencies depending on the installed version of Bolt.

### Bolt >= 1.38.0 < 3.0.0

The recommended procedure for these versions is to use a [Bolt Puppetfile](https://puppet.com/docs/bolt/latest/installing_tasks_from_the_forge.html#task-8928).
From within a [Boltdir](https://puppet.com/docs/bolt/latest/bolt_project_directories.html#embedded-project-directory), specify this module and `puppetlabs-stdlib` as dependencies and run `bolt puppetfile install`.  For example:

```bash
mkdir -p ~/Boltdir
cd ~/Boltdir

cat >>Puppetfile <<EOF
mod 'puppetlabs-stdlib'

mod 'puppetlabs-ca_extend'
EOF

bolt puppetfile install
```

### Bolt >= 3.0.0

The recommended procedure for these versions is to use a Bolt Project.  When creating a [Bolt project](https://puppet.com/docs/bolt/latest/bolt_project_directories.html#embedded-project-directory), specify this module and `puppetlabs-stdlib` as dependencies and initialize the project.  For example:

```bash
sudo rpm -Uvh https://yum.puppet.com/puppet-tools-release-el-7.noarch.rpm
sudo yum install puppet-bolt
```

If your primary Puppet server or workstation has internet access, the project can be initialized with the needed dependencies with the following:

```bash
mkdir ca_extend
cd ca_extend

bolt project init expiry --modules puppetlabs-stdlib,puppetlabs-ca_extend
```

Otherwise, if your primary Puppet server or workstation operates behind a proxy, initialize the project without the `--modules` option:

```bash
mkdir ca_extend
cd ca_extend

bolt project init expiry
```

Then edit your `bolt-project.yaml` to use the proxy according to the [documentation](https://puppet.com/docs/bolt/latest/bolt_installing_modules.html#install-modules-using-a-proxy).  Next, add the module dependencies to `bolt-project.yaml`:

```yaml
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

See the "Usage" section for how to run the tasks and plans remotely or locally on the primary Puppet server.

### Dependencies

*  A [Puppet Bolt](https://puppet.com/docs/bolt/latest/bolt_installing.html) >= 1.38.0
*  [puppetlabs-stdlib](https://puppet.com/docs/bolt/latest/bolt_installing.html)
*  A `base64` binary on the primary Puppet server which supports the `-w` flag
*  `bash` >= 4.0 on the primary Puppet server

## Usage

### Extend the CA using the ca_extend::extend_ca_cert plan

First, check the expiration of the Puppet agent certificate by running the following command as root on the primary Puppet server:

```bash
/opt/puppetlabs/puppet/bin/openssl x509 -in "$(/opt/puppetlabs/bin/puppet config print hostcert)" -enddate -noout
```

If, and only if, the `notAfter` date printed has already passed, then the primary Puppet server certificate has expired and must be cleaned up before the CA can be regenerated.  This can be accomplished by passing `regen_primary_cert=true` to the `ca_extend::extend_ca_cert` plan.

> Note: This plan will also run the `ca_extend::check_crl_cert` task and if the crl is expired, will automatically resolve the issue by running the `ca_extend::crl_truncate` task.

```bash
bolt plan run ca_extend::extend_ca_cert regen_primary_cert=true --targets <primary_fqdn> replica=<replica_fqdn> compilers=<comma_separated_compiler_fqdns> --run-as root
```

Note that if you are running `extend_ca_cert` locally on the primary Puppet server, you can avoid potential Bolt transport issues by specifying `--targets local://hostname`, e.g.

```bash
bolt plan run ca_extend::extend_ca_cert --targets local://hostname --run-as root
```

### Distribute `ca.pem` to agents 

Next, distribute `ca.pem` to agents using one of the three methods:

#### 1. Using the ca_extend::upload_ca_cert Plan

Using the `ca_extend::upload_ca_cert` plan relies on using `ssh` and/or `winrm` transport methods. Use the `cert` parameter to specify the location of the updated CA cert on the primary server. For example, you may use `cert=$(puppet config print localcacert)`. Distribute the CA certificate to agent nodes specified in the `targets` parameter. Bolt defaults to using `ssh` transport, which in turn will use `~/.ssh/config` for options such as `username` and `private-key`. However, the `ca_extend::upload_ca_cert` plan works best with a Bolt [inventory file](https://puppet.com/docs/bolt/latest/inventory_file.html) to specify `targets`; this allows for simultaneous uploads to \*nix and Windows agents. See the Bolt documentation for more information on configuring an inventory file and the `targets` parameter.

```bash
bolt plan run ca_extend::upload_ca_cert cert=<path_to_cert> --targets <TargetSpec>
```

As an alternative to using the `targets` parameter, you may specify targets for the `ca_extend::upload_ca_cert` plan by connecting Bolt to [PuppetDB](https://puppet.com/docs/bolt/latest/bolt_connect_puppetdb.html), after which the [--query](https://puppet.com/docs/bolt/latest/bolt_command_reference.html#command-options) parameter can be used. 

Example query for all agent nodes excluding puppetserver nodes because the `ca_extend::extend_ca_cert` plan already updates the primary's and compilers' copies of the CA certificate:

```bash
bolt plan run ca_extend::upload_ca_cert cert=<path_to_cert> --query "nodes[certname]{! certname in ['primaryfqdn', 'compiler1fqdn', 'compiler2fqdn']}"
```

#### 2. Manually deleting `ca.pem` on agents and letting them download that file as part of the next Puppet agent run

The agent will download `ca.pem` only if it is absent, so it must be deleted to use this method. 

For example, on an \*nix agent node delete `ca.pem` by running:

```bash
rm $(puppet config print localcacert)
```

Next, run puppet so the agent will retreive `ca.pem`:

```bash
puppet agent -t
```

**Note:** If you are depending on agent nodes downloading `ca.pem` during a scheduled Puppet run rather than manually initiating a Puppet run with `puppet agent -t`, you may need to restart the `puppet` service on \*nix nodes. This is because the Puppet agent daemon on \*nix nodes could have previous CA content loaded into memory. 

#### 3. Using a Puppet file resource to manage `ca.pem`


You may add this code to the catalog received by your agent nodes; the code manages `ca.pem` on Windows and \*nix nodes with the contents of `ca.pem` on the compiling server (primary server or compiler). The code will not work with a serverless approach such as `puppet apply`. _Note: This method is only possible if the CA certificate has not yet expired because Puppet communications depend upon a valid CA certificate._

```
  $localcacert = $facts['os']['family'] ? {
    'windows' => 'C:\ProgramData\PuppetLabs\puppet\etc\ssl\certs\ca.pem',
    default   => '/etc/puppetlabs/puppet/ssl/certs/ca.pem'
  }
  file {$localcacert:
    ensure  => file,
    content => file($settings::localcacert),
  }
```

### ca_extend::check_ca_expiry Task

You can use this task to check the CA cert expiry on the `primary` mainly but you can also use it to check that a remote \*nix node's CA cert has been updated after using any means to distribute the new CA certificate.

```bash
bolt task run ca_extend::check_ca_expiry --targets <TargetSpec>
```

### ca_extend::check_agent_expiry Task

You can use this task to categorize all PE certs in a PE environment as part of a valid or expiring section based on a customizable date in the future (default 3 months from now). This task runs against a `primary` server and checks all certs under `/etc/puppetlabs/puppet/ssl/ca/signed` as the single source of truth for the PE environment and splits the certs between a valid section or expiring section.

```bash
bolt task run ca_extend::check_agent_expiry --targets local://hostname
```

As such, the following output illustrates that all available certs in `/etc/puppetlabs/puppet/ssl/ca/signed` are valid and nothing is expiring in the next 3 months.

```bash
[root@pe-server-7a5b76-0 ca_extend]# bolt task run ca_extend::check_agent_expiry --targets local://hostname
Started on local://pe-server-7a5b76-0.us-west1-c.internal...
Finished on local://pe-server-7a5b76-0.us-west1-c.internal:
  {
    "valid": [
      {
        "console-cert.pem": "Jan 14 19:55:34 2024 GMT"
      },
      {
        "critical-boom.delivery.puppetlabs.net.pem": "Apr 21 17:57:20 2027 GMT"
      },
      {
        "irate-maple.delivery.puppetlabs.net.pem": "Apr 21 19:25:35 2027 GMT"
      }
    ],
    "expired": [

    ]
  }

Successful on 1 target: local://pe-server-7a5b76-0.us-west1-c.internal
Ran on 1 target in 1.32 sec
```

See `REFERENCE.md` for more detailed examples.

## Reference

Puppet's security is based on a PKI using X.509 certificates.

This module's `ca_extend::extend_ca_cert` plan re-issues the CA certificate (the root self-signed, an intermediate under the re-issued root) using the same keypair as before. The new certificate has the same:

* Keypair.
* Subject.
* Issuer.
* Serial number.
* Validity start (notBefore).
* X509v3 Subject Key Identifier (the fingerprint of the public key).
* Every other extension (basic constraints with any pathlen, key usage, custom extensions), byte for byte.

A certificate that is re-issued (not one that is kept because it already expires no earlier than the new end date) has a different:

* Validity end (notAfter), which is the point of the whole exercise.
* Signature (since the validity period changed).
* Authority Key Identifier, only if the old one named a different key id or issuer: it is rebuilt from the issuer, so it is byte for byte the old one otherwise. It names the issuer by DN and serial only if the old one did.

Since Puppet's services (and other services that use Puppet's PKI) validate certificates by trusting a self-signed CA and comparing its public key to the Signatures and Authority Key Identifiers of the certificates it has issued,
it's possible to re-issue a CA certificate based on a prior keypair without invalidating any certificates issued by the old CA.
Once you've done that, it's just a matter of delivering the new CA certificate to every participant in the PKI.

## How to Report an issue or contribute to the module

If you are a PE user and need support using this module or are encountering issues, our Support team would be happy to help you resolve your issue and help reproduce any bugs. Just raise a ticket on the [support portal](https://support.puppet.com/hc/en-us/requests/new).

If you have a reproducible bug or are a community user you can raise it directly on the Github issues page of the module [here.](https://github.com/puppetlabs/ca_extend/issues) We also welcome PR contributions to improve the module. Please see further details about contributing [here](https://puppet.com/docs/puppet/7.5/contributing.html#contributing_changes_to_module_repositories)


---

# Supporting Content

### Articles

The [Support Knowledge base](https://support.puppet.com/hc/en-us) is a searchable repository for technical information and how-to guides for all Puppet products.

This Module has the following specific Article(s) available:

1. [Check and fix the expiry date for your CA certificate in Puppet Enterprise](https://support.puppet.com/hc/en-us/articles/360022508353)


### Videos

The [Support Video Playlist](https://youtube.com/playlist?list=PLV86BgbREluWKzzvVulR74HZzMl6SCh3S) is a resource of content generated by the support team

   
   ---

