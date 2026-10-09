# @summary
#   Plan that extends the Puppet CA certificate and configures the primary Puppet server
#   and Compilers to use the extended certificate.
# @param targets The target node on which to run the plan.  Should be the primary Puppet server
# @param compilers Optional comma separated list of compilers to configure to use the extended CA
# @param replica Optional replica to configure to use the extended CA
# @param psql_nodes Optional comma separated list of psql nodes to configure to use the extended CA
# @param ssldir Location of the ssldir on disk
# @param regen_primary_cert Whether to also regenerate the agent certificate of the primary Puppet server
# @example Extend the CA cert and regenerate the primary agent cert locally on the primary Puppet server
#   bolt plan run ca_extend::extend_ca_cert regen_primary_cert=true --targets local://$(hostname -f) --run-as root
# @example Extend the CA cert by running the plan remotely
#   bolt plan run ca_extend::extend_ca_cert --targets <primary_fqdn> --run-as root
plan ca_extend::extend_ca_cert(
  TargetSpec $targets,
  Optional[TargetSpec] $compilers = undef,
  Optional[TargetSpec] $replica = undef,
  Optional[TargetSpec] $psql_nodes = undef,
  $ssldir                               = '/etc/puppetlabs/puppet/ssl',
  $regen_primary_cert                   = false,
) {
  $targets.apply_prep
  $primary_facts = run_task('facts', $targets, '_catch_errors' => true).first

  if $primary_facts['pe_build'] {
    $is_pe = true

    $primary_services = [
      'puppet',
      'pe-puppetserver',
      'pe-postgresql',
      'pe-puppetdb',
      'pe-ace-server',
      'pe-bolt-server',
      'pe-console-services',
      'pe-orchestration-services',
    ]
    $replica_services = ['pe-puppetserver', 'pe-postgresql', 'pe-puppetdb', 'pe-console-services']
  }
  elsif $primary_facts['puppetversion'] {
    $is_pe = false
    $primary_services = ['puppet', 'puppetserver']
  }
  else {
    fail_plan("Puppet not detected on ${targets}")
  }

  if $is_pe and ! $regen_primary_cert {
    $out = run_task('ca_extend::check_primary_cert', $targets, '_catch_errors' => true).first
    unless $out.ok {
      fail_plan($out.value['message'])
    }
    if $out.value['status'] == 'warn' {
      warning($out.value['message'])
    }
  }

  if $is_pe {
    $crl_results = run_task('ca_extend::check_crl_cert', $targets).first
    if $crl_results['status'] == 'expired' {
      out::message('INFO: CRL expired, truncating to regenerate')
      run_task('ca_extend::crl_truncate', $targets)
    }
  }

  out::message("INFO: Stopping Puppet services on ${targets}")
  $primary_services.each |$service| {
    run_task('service::linux', $targets, 'action' => 'stop', 'name' => $service)
  }

  out::message("INFO: Extending CA certificate on ${targets}")
  $regen_results = run_task('ca_extend::extend_ca_cert', $targets)
  $new_cert = $regen_results.first.value
  $cert_contents = base64('decode', $new_cert['contents'])

  out::message("INFO: Configuring ${targets} to use the extended CA certificate")
  if $is_pe {
    run_task('ca_extend::configure_primary', $targets,
      'new_cert' => $new_cert['new_cert'], 'regen_primary_cert' => $regen_primary_cert
    )
  }
  else {
    run_command("/bin/cp ${new_cert['new_cert']} ${ssldir}/certs/ca.pem", $targets)
    run_command("/bin/cp ${new_cert['new_cert']} ${ssldir}/ca/ca_crt.pem", $targets)
    run_task('service::linux', $targets, 'action' => 'start', 'name' => 'puppetserver')
  }

  $tmp = run_command('mktemp', 'localhost', '_run_as' => system::env('USER'))
  $tmp_file = $tmp.first.value['stdout'].chomp
  file::write($tmp_file, $cert_contents)

  run_command('/opt/puppetlabs/bin/puppet agent --no-daemonize --no-noop --onetime', $targets)
  run_task('service::linux', $targets, 'action' => 'start', 'name' => 'puppet')

  if $is_pe and $replica {
    out::message("INFO: Stopping Puppet services on ${replica}")
    # Stop and start the puppet service manually on replicas
    run_task('service::linux', $replica, 'action' => 'stop', 'name' => 'puppet')

    $replica_services.each |$service| {
      run_task('service::linux', $replica, 'action' => 'stop', 'name' => $service)
    }

    out::message("INFO: Configuring the replica (${replica}) to use the extended CA certificate")
    upload_file($tmp_file, '/etc/puppetlabs/puppet/ssl/certs/ca.pem', $replica)

    # Run the agent to restart the appropriate services
    out::message("INFO: running Puppet agent on ${replica}")
    run_command('/opt/puppetlabs/bin/puppet agent --no-daemonize --no-noop --onetime', $replica)

    # Re-enable the Puppet service
    run_task('service::linux', $compilers, 'action' => 'start', 'name' => 'puppet')
  }

  if $compilers {
    out::message("INFO: Stopping Puppet services on compilers (${compilers})")
    run_task('service::linux', $compilers, 'action' => 'stop', 'name' => 'puppet')

    out::message("INFO: Configuring compilers (${compilers}) to use the extended CA certificate")
    upload_file($tmp_file, '/etc/puppetlabs/puppet/ssl/certs/ca.pem', $compilers)

    if $is_pe {
      # Use the service::linux task to check if PDB is running on compilers and restart it if so
      $pdb_compilers = run_task('service::linux', $compilers, 'action' => 'status', 'name' => 'pe-puppetdb').filter_set |$compiler| {
      $compiler['enabled'] !~ /^Failed to get unit file state/ }.map |$result| {
        $result.target
      }
      $legacy_compilers = get_targets($compilers) - $pdb_compilers

      unless $pdb_compilers.empty {
        out::message('INFO: stopping services on PDB compilers')
        ['pe-puppetserver', 'pe-puppetdb'].each |$service| {
          run_task('service::linux', $pdb_compilers, 'action' => 'stop', 'name' => $service)
        }
      }

      unless $legacy_compilers.empty {
        out::message('INFO: stopping services on legacy compilers')
        run_task('service::linux', $legacy_compilers, 'action' => 'stop', 'name' => 'pe-puppetserver')
      }
    }
    else {
      out::message('INFO: stopping services on compilers')
      run_task('service::linux', $compilers, 'action' => 'stop', 'name' => 'pe-puppetserver')
    }

    # Run the agent to restart the appropriate services
    out::message("INFO: running Puppet agent on ${compilers}")
    run_command('/opt/puppetlabs/bin/puppet agent --no-daemonize --no-noop --onetime', $compilers)

    # Re-enable the Puppet service
    run_task('service::linux', $compilers, 'action' => 'start', 'name' => 'puppet')
  }

  if $psql_nodes {
    out::message("INFO: Stopping Puppet services on psql nodes (${psql_nodes})")
    ['puppet', 'pe-postgresql'].each |$service| {
      run_task('service::linux', $psql_nodes, 'action' => 'stop', 'name' => $service)
    }

    out::message("INFO: Configuring psql nodes (${psql_nodes}) to use the extended CA certificate")
    upload_file($tmp_file, '/etc/puppetlabs/puppet/ssl/certs/ca.pem', $psql_nodes)

    # Run the agent to restart the appropriate services
    out::message("INFO: running Puppet agent on ${psql_nodes}")
    run_command('/opt/puppetlabs/bin/puppet agent --no-daemonize --no-noop --onetime', $psql_nodes)

    # Re-enable the Puppet service
    run_task('service::linux', $psql_nodes, 'action' => 'start', 'name' => 'puppet')
  }

  out::message("INFO: Extended CA certificate decoded and stored at ${tmp_file}")
  out::message("INFO: Run the 'ca_extend::upload_ca_cert' plan to distribute the extended CA certificate to agents")
}
