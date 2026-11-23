# frozen_string_literal: true

require 'spec_helper_acceptance'
require 'json'
require 'time'

# The filesystem re-sign must keep what the CA certificates carry (pathlen, keyUsage,
# criticality, every extension) on the OpenSSL of the target. The FIPS example runs only on a
# target that is in FIPS mode; the CI matrix has no such platform, so it is skipped there.
describe 'extend_ca_cert task keeps the extensions of the CA certificates' do
  let(:compare_script) { File.expand_path('../support/compare_ca_bundles.rb', __dir__) }
  let(:ruby) { '/opt/puppetlabs/puppet/bin/ruby' }

  def fips_enabled?
    run_shell('cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo 0').stdout.strip == '1'
  end

  # extend.sh names the new bundle ca_crt-expires-YYMMDDHHMMSSZ.pem after the end date it asked
  # for. Giving the compare script that date lets it accept a certificate that extend.sh kept
  # unchanged because it already expires no earlier than that date; without it the script reports
  # such a certificate as "notAfter not later". Only a byte-identical certificate is waived.
  def requested_not_after(bundle)
    stamp = bundle[%r{ca_crt-expires-(\d{12})Z\.pem}, 1]
    raise "no end date in the bundle name: #{bundle}" unless stamp

    year, month, day, hour, minute, second = stamp.scan(%r{\d\d}).map(&:to_i)
    Time.utc(2000 + year, month, day, hour, minute, second).iso8601
  end

  def extended_bundle_problems
    old_bundle = run_shell('/opt/puppetlabs/puppet/bin/puppet config print --section master cacert').stdout.strip
    task = run_bolt_task('ca_extend::extend_ca_cert')
    # Litmus hands the task's result back as text, in Ruby's inspect form ("new_cert"=>"..."), not JSON.
    new_bundle = task.stdout[%r{"new_cert"\s*(?:=>|:)\s*"([^"]+)"}, 1]
    raise "no new_cert in the task output: #{task.stdout[0, 500]}" unless new_bundle

    bolt_upload_file(compare_script, '/tmp/compare_ca_bundles.rb')
    requested = requested_not_after(new_bundle)
    JSON.parse(run_shell("#{ruby} /tmp/compare_ca_bundles.rb #{old_bundle} #{new_bundle} #{requested}").stdout)
  end

  it 'extends the CA certificates and keeps their subject, key, serial, notBefore and extensions' do
    expect(extended_bundle_problems).to eq([])
  end

  context 'on a FIPS-mode host' do
    it 'does the same under the FIPS OpenSSL' do
      skip 'this host is not in FIPS mode; the CI matrix (spec/fixtures/matrix) has no FIPS platform' unless fips_enabled?
      expect(extended_bundle_problems).to eq([])
    end
  end
end
