# frozen_string_literal: true

require_relative 'unit_helper'
require 'openssl'
require 'open3'
require 'rbconfig'
require 'stringio'
require 'tmpdir'
require_relative '../../files/extend_cert'

# Specs for the command-line entry point (files/extend_cert.rb) that extend.sh runs
# with /opt/puppetlabs/puppet/bin/ruby.
RSpec.describe 'CaExtend::ExtendCertCli' do
  cli_script = File.expand_path('../../files/extend_cert.rb', __dir__)
  puppet_ruby = '/opt/puppetlabs/puppet/bin/ruby'

  let(:dir) { Dir.mktmpdir('extend_cert_cli') }
  let(:root_key) { CaExtendSpecKeys::ROOT }
  let(:int_key) { CaExtendSpecKeys::INTERMEDIATE }
  let(:root) { make_cert('Puppet CA: root', root_key, root_key, nil, 'CA:TRUE,pathlen:1') }
  let(:int) { make_cert('Puppet CA: intermediate', int_key, root_key, root, 'CA:TRUE,pathlen:0') }
  let(:not_after) { (Time.now + (10 * 365 * 86_400)).utc.strftime('%Y-%m-%dT%H:%M:%SZ') }
  let(:out_file) { path('out.pem') }

  before(:each) do
    File.write(path('root.pem'), root.to_pem)
    File.write(path('root_key.pem'), root_key.to_pem)
    File.write(path('int.pem'), int.to_pem)
    File.write(path('other_key.pem'), CaExtendSpecKeys::OTHER.to_pem)
    File.write(path('int_key.pem'), int_key.to_pem)
  end

  after(:each) { FileUtils.remove_entry(dir) }

  def make_cert(cn, key, issuer_key, issuer, constraints)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = issuer ? 2 : 1
    cert.subject = OpenSSL::X509::Name.new([['CN', cn]])
    cert.issuer = issuer ? issuer.subject : cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now - (365 * 86_400)
    cert.not_after = Time.now + (30 * 86_400)
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = cert
    factory.issuer_certificate = issuer || cert
    cert.add_extension(factory.create_extension('basicConstraints', constraints, true))
    cert.add_extension(factory.create_extension('subjectKeyIdentifier', 'hash', false))
    cert.add_extension(factory.create_extension('authorityKeyIdentifier', 'keyid,issuer:always', false))
    cert.sign(issuer_key, OpenSSL::Digest.new('SHA256'))
    cert
  end

  def path(name)
    File.join(dir, name)
  end

  def run_cli(*args)
    out = StringIO.new
    err = StringIO.new
    status = CaExtend::ExtendCertCli.run(args, out, err)
    [status, out.string, err.string]
  end

  it 'extends a root and writes the PEM only to --out' do
    status, stdout, stderr = run_cli('--cert', path('root.pem'), '--key', path('root_key.pem'),
                                     '--not-after', not_after, '--out', out_file)
    expect(status).to eq(0), stderr
    expect(stdout).to eq('')
    new = OpenSSL::X509::Certificate.new(File.read(out_file))
    expect(new.subject.to_der).to eq(root.subject.to_der)
    expect(new.serial).to eq(root.serial)
    expect(new.not_after).to be > root.not_after
    expect(new.verify(root_key)).to be(true)
    expect(new.extensions.find { |e| e.oid == 'basicConstraints' }.value).to eq('CA:TRUE, pathlen:1')
  end

  it 'extends an intermediate under a re-issued root with --issuer-cert' do
    status, _, stderr = run_cli('--cert', path('root.pem'), '--key', path('root_key.pem'),
                                '--not-after', not_after, '--out', path('root.new.pem'))
    expect(status).to eq(0), stderr
    status, _, stderr = run_cli('--cert', path('int.pem'), '--issuer-cert', path('root.new.pem'),
                                '--key', path('root_key.pem'), '--not-after', not_after, '--out', out_file)
    expect(status).to eq(0), stderr
    new = OpenSSL::X509::Certificate.new(File.read(out_file))
    store = OpenSSL::X509::Store.new
    store.add_cert(OpenSSL::X509::Certificate.new(File.read(path('root.new.pem'))))
    expect(store.verify(new)).to be(true), store.error_string
  ensure
    FileUtils.rm_f(path('root.new.pem'))
  end

  it 'writes nothing and says why when the key does not match the issuing certificate' do
    status, stdout, stderr = run_cli('--cert', path('root.pem'), '--key', path('other_key.pem'),
                                     '--not-after', not_after, '--out', out_file)
    expect(status).to eq(1)
    expect(stdout).to eq('')
    expect(stderr).to match(%r{ERROR: .*does not match the issuing certificate})
    expect(File.exist?(out_file)).to be(false)
  end

  # extend.sh asks for now + 15 years for both certificates; a root that already outlives that
  # cannot be re-issued (not later), but renewing its intermediate must not be blocked.
  context 'with --keep-if-sufficient' do
    let(:soon) { (Time.now + (10 * 86_400)).utc.strftime('%Y-%m-%dT%H:%M:%SZ') }

    it 'is refused as not later without the flag' do
      status, _, stderr = run_cli('--cert', path('root.pem'), '--key', path('root_key.pem'),
                                  '--not-after', soon, '--out', out_file)
      expect(status).to eq(1)
      expect(stderr).to match(%r{ERROR: .*not later than the current})
    end

    it 'writes a certificate that already expires later unchanged, and says so' do
      status, stdout, stderr = run_cli('--cert', path('root.pem'), '--key', path('root_key.pem'),
                                       '--not-after', soon, '--keep-if-sufficient', '--out', out_file)
      expect(status).to eq(0), stderr
      expect(stdout).to eq('')
      expect(stderr).to match(%r{already expires.*kept unchanged})
      expect(File.read(out_file)).to eq(root.to_pem)
    end

    it 'keeps an intermediate under its issuer certificate, and refuses an issuer certificate that is not its issuer' do
      status, _, stderr = run_cli('--cert', path('int.pem'), '--issuer-cert', path('root.pem'), '--key', path('root_key.pem'),
                                  '--not-after', soon, '--keep-if-sufficient', '--out', out_file)
      expect(status).to eq(0), stderr
      expect(File.read(out_file)).to eq(int.to_pem)
      File.delete(out_file)
      status, _, stderr = run_cli('--cert', path('int.pem'), '--issuer-cert', path('int.pem'), '--key', path('int_key.pem'),
                                  '--not-after', soon, '--keep-if-sufficient', '--out', out_file)
      expect(status).to eq(1)
      expect(stderr).to match(%r{not by the given issuer certificate})
      expect(File.exist?(out_file)).to be(false)
    end

    it 'still re-issues a certificate that expires before the requested notAfter' do
      status, _, stderr = run_cli('--cert', path('root.pem'), '--key', path('root_key.pem'),
                                  '--not-after', not_after, '--keep-if-sufficient', '--out', out_file)
      expect(status).to eq(0), stderr
      expect(stderr).not_to match(%r{kept unchanged})
      expect(OpenSSL::X509::Certificate.new(File.read(out_file)).not_after).to be > root.not_after
    end

    it 'still refuses a key that does not match, and a requested notAfter in the past, writing nothing' do
      status, _, stderr = run_cli('--cert', path('root.pem'), '--key', path('other_key.pem'),
                                  '--not-after', soon, '--keep-if-sufficient', '--out', out_file)
      expect(status).to eq(1)
      expect(stderr).to match(%r{does not match the issuing certificate})
      status, _, stderr = run_cli('--cert', path('root.pem'), '--key', path('root_key.pem'),
                                  '--not-after', '200101000000Z', '--keep-if-sufficient', '--out', out_file)
      expect(status).to eq(1)
      expect(stderr).to match(%r{must lie in the future})
      expect(File.exist?(out_file)).to be(false)
    end
  end

  it 'writes nothing when the notAfter is refused' do
    status, _, stderr = run_cli('--cert', path('root.pem'), '--key', path('root_key.pem'),
                                '--not-after', '200101000000Z', '--out', out_file)
    expect(status).to eq(1)
    expect(stderr).to match(%r{ERROR: .*must lie in the future})
    expect(File.exist?(out_file)).to be(false)
  end

  it 'rejects an unreadable input with a message, not a stack trace' do
    status, _, stderr = run_cli('--cert', path('nope.pem'), '--key', path('root_key.pem'),
                                '--not-after', not_after, '--out', out_file)
    expect(status).to eq(1)
    expect(stderr).to match(%r{ERROR: .*nope\.pem})
    expect(stderr).not_to match(%r{\.rb:\d+})
  end

  it 'rejects input that is not a certificate or key' do
    File.write(path('junk.pem'), 'not pem')
    status, _, stderr = run_cli('--cert', path('junk.pem'), '--key', path('root_key.pem'),
                                '--not-after', not_after, '--out', out_file)
    expect(status).to eq(1)
    expect(stderr).to match(%r{ERROR: .*junk\.pem})
    status, _, stderr = run_cli('--cert', path('root.pem'), '--key', path('junk.pem'),
                                '--not-after', not_after, '--out', out_file)
    expect(status).to eq(1)
    expect(stderr).to match(%r{ERROR: .*junk\.pem})
  ensure
    FileUtils.rm_f(path('junk.pem'))
  end

  it 'leaves an existing --out untouched, and no temporary file, when the final rename fails' do
    File.write(out_file, 'previous contents')
    allow(File).to receive(:rename).and_call_original
    allow(File).to receive(:rename).with(%r{\.tmp\z}, out_file).and_raise(Errno::EACCES)
    status, _, stderr = run_cli('--cert', path('root.pem'), '--key', path('root_key.pem'),
                                '--not-after', not_after, '--out', out_file)
    expect(status).to eq(1)
    expect(stderr).to match(%r{ERROR: Cannot write})
    expect(File.read(out_file)).to eq('previous contents')
    expect(Dir.glob(File.join(dir, '*.tmp'))).to eq([])
  end

  it 'refuses a key of a type without a private? test (Ed25519) with one ERROR line' do
    begin
      ed = OpenSSL::PKey.generate_key('ED25519')
    rescue StandardError
      skip 'this OpenSSL cannot generate an Ed25519 key'
    end
    File.write(path('ed.pem'), ed.private_to_pem)
    status, _, stderr = run_cli('--cert', path('root.pem'), '--key', path('ed.pem'),
                                '--not-after', not_after, '--out', out_file)
    expect(status).to eq(1)
    expect(stderr.lines.size).to eq(1)
    expect(stderr).to start_with('ERROR: ')
    expect(File.exist?(out_file)).to be(false)
  end

  it 'refuses an unwritable --out' do
    status, _, stderr = run_cli('--cert', path('root.pem'), '--key', path('root_key.pem'),
                                '--not-after', not_after, '--out', path('no/such/dir/out.pem'))
    expect(status).to eq(1)
    expect(stderr).to match(%r{ERROR: .*out\.pem})
  end

  it 'refuses a public key given as --key with one ERROR line' do
    File.write(path('pub.pem'), root_key.public_key.to_pem)
    status, _, stderr = run_cli('--cert', path('root.pem'), '--key', path('pub.pem'),
                                '--not-after', not_after, '--out', out_file)
    expect(status).to eq(1)
    expect(stderr.lines.size).to eq(1)
    expect(stderr).to match(%r{ERROR: .*pub\.pem is not a private key})
    expect(File.exist?(out_file)).to be(false)
  end

  it 'reports an argument that is not valid UTF-8 as a usage error, not a stack trace' do
    status, _, stderr = run_cli('--cert', path('root.pem'), '--key', path('root_key.pem'),
                                '--not-after', "20\xff41-01-01T00:00:00Z".dup.force_encoding('UTF-8'), '--out', out_file)
    expect(status).to eq(2)
    expect(stderr).to start_with('ERROR: ')
  end

  it 'prints usage and fails when a required option is missing' do
    status, _, stderr = run_cli('--cert', path('root.pem'))
    expect(status).to eq(2)
    expect(stderr).to match(%r{missing.*--key}i)
    expect(stderr).to match(%r{Usage:})
  end

  it 'accepts a UTCTime --not-after as well' do
    utc = (Time.now + (10 * 365 * 86_400)).utc.strftime('%y%m%d%H%M%SZ')
    status, _, stderr = run_cli('--cert', path('root.pem'), '--key', path('root_key.pem'),
                                '--not-after', utc, '--out', out_file)
    expect(status).to eq(0), stderr
    expect(OpenSSL::X509::Certificate.new(File.read(out_file)).not_after).to eq(Time.utc(*utc.scan(%r{\d\d}).first(6).map(&:to_i).tap { |a| a[0] += 2000 }))
  end

  [['an empty extnValue', '', %r{broken_root\.pem}],
   ['trailing bytes', "\x04\x01\x05\x00".b, %r{broken_root\.pem}],
   ['a zero-length id', "\x04\x00".b, %r{subjectKeyIdentifier of .*Puppet CA: root.* is empty}]].each do |label, value, message|
    it "reports a root issuer with a malformed SKI (#{label}) as one ERROR line, without writing" do
      bad_ski = OpenSSL::X509::Extension.new(
        OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId.new('subjectKeyIdentifier'),
                                     OpenSSL::ASN1::OctetString.new(value)]).to_der,
      )
      broken_root = OpenSSL::X509::Certificate.new(root.to_der)
      broken_root.not_after = Time.now + (11 * 365 * 86_400)
      broken_root.extensions = broken_root.extensions.map { |e| (e.oid == 'subjectKeyIdentifier') ? bad_ski : e }
      broken_root.sign(root_key, OpenSSL::Digest.new('SHA256'))
      File.write(path('broken_root.pem'), broken_root.to_pem)
      status, stdout, stderr = run_cli('--cert', path('int.pem'), '--key', path('root_key.pem'),
                                       '--issuer-cert', path('broken_root.pem'),
                                       '--not-after', not_after, '--out', out_file)
      expect(status).to eq(1)
      expect(stdout).to eq('')
      expect(stderr.lines.size).to eq(1)
      expect(stderr).to match(message)
      expect(File.exist?(out_file)).to be(false)
    end
  end

  it 'reports an OpenSSL failure as one ERROR line, not a stack trace' do
    bad_aki = OpenSSL::X509::Extension.new(
      OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId.new('authorityKeyIdentifier'),
                                   OpenSSL::ASN1::OctetString.new('not der')]).to_der,
    )
    broken = make_cert('Puppet CA: broken', root_key, root_key, nil, 'CA:TRUE')
    broken.extensions = broken.extensions.reject { |e| e.oid == 'authorityKeyIdentifier' } + [bad_aki]
    broken.sign(root_key, OpenSSL::Digest.new('SHA256'))
    File.write(path('broken.pem'), broken.to_pem)
    status, stdout, stderr = run_cli('--cert', path('broken.pem'), '--key', path('root_key.pem'),
                                     '--not-after', not_after, '--out', out_file)
    expect(status).to eq(1)
    expect(stdout).to eq('')
    expect(stderr).to match(%r{\AERROR: .*broken\.pem}m)
    expect(stderr.lines.size).to eq(1)
    expect(File.exist?(out_file)).to be(false)
  end

  it 'fails fast, without prompting, on a passphrase-protected key' do
    cipher = OpenSSL::Cipher.new('aes-128-cbc')
    File.write(path('locked_key.pem'), root_key.to_pem(cipher, 'secret'))
    status, _, stderr = run_cli('--cert', path('root.pem'), '--key', path('locked_key.pem'),
                                '--not-after', not_after, '--out', out_file)
    expect(status).to eq(1)
    expect(stderr).to match(%r{ERROR: .*locked_key\.pem is not a private key})
  end

  it 'prints usage and fails on a stray argument' do
    status, _, stderr = run_cli('--cert', path('root.pem'), '--key', path('root_key.pem'),
                                '--not-after', not_after, '--out', out_file, 'stray')
    expect(status).to eq(2)
    expect(stderr).to match(%r{unexpected argument.*stray})
    expect(File.exist?(out_file)).to be(false)
  end

  it 'prints usage and fails on an unknown option' do
    status, _, stderr = run_cli('--bogus')
    expect(status).to eq(2)
    expect(stderr).to match(%r{Usage:})
  end

  it 'prints usage and exits 0 for --help' do
    status, stdout, = run_cli('--help')
    expect(status).to eq(0)
    expect(stdout).to match(%r{Usage:})
  end

  # The real entry point, as extend.sh runs it: a separate process.
  [RbConfig.ruby, puppet_ruby].uniq.each do |ruby|
    context "run as #{ruby}" do
      before(:each) { skip "#{ruby} is not installed on this machine" unless File.executable?(ruby) }

      it 'extends a root and exits 0' do
        stdout, stderr, status = Open3.capture3(ruby, cli_script, '--cert', path('root.pem'), '--key', path('root_key.pem'),
                                                '--not-after', not_after, '--out', out_file)
        expect(status.exitstatus).to eq(0), "#{stdout}#{stderr}"
        new = OpenSSL::X509::Certificate.new(File.read(out_file))
        expect(new.verify(root_key)).to be(true)
        # A v1 certificate cannot carry extensions: PE's Ruby 2.5 makes one unless the version is set.
        expect(new.version).to eq(2)
        # What this Ruby and its OpenSSL built must be what the in-process run builds:
        # the same extensions, byte for byte (pathlen, criticality, rebuilt AKI included).
        expected = CaExtend::Reissue.reissue(root, issuer_cert: nil, issuer_key: root_key, not_after: new.not_after)
        expect(new.extensions.map(&:to_der)).to eq(expected.extensions.map(&:to_der))
        expect(new.extensions.find { |e| e.oid == 'basicConstraints' }.value).to eq('CA:TRUE, pathlen:1')
      end

      it 'extends an intermediate under the re-issued root, byte for byte as in process' do
        root_out = path('root.new.pem')
        _, stderr, status = Open3.capture3(ruby, cli_script, '--cert', path('root.pem'), '--key', path('root_key.pem'),
                                           '--not-after', not_after, '--out', root_out)
        expect(status.exitstatus).to eq(0), stderr
        _, stderr, status = Open3.capture3(ruby, cli_script, '--cert', path('int.pem'), '--issuer-cert', root_out,
                                           '--key', path('root_key.pem'), '--not-after', not_after, '--out', out_file)
        expect(status.exitstatus).to eq(0), stderr
        new = OpenSSL::X509::Certificate.new(File.read(out_file))
        new_root = OpenSSL::X509::Certificate.new(File.read(root_out))
        expected = CaExtend::Reissue.reissue(int, issuer_cert: new_root, issuer_key: root_key, not_after: new.not_after)
        expect(new.extensions.map(&:to_der)).to eq(expected.extensions.map(&:to_der))
        expect(new.version).to eq(2)
        expect(new.verify(root_key)).to be(true)
      end

      it 'exits 1 with an ERROR line and writes nothing on a key mismatch' do
        _, stderr, status = Open3.capture3(ruby, cli_script, '--cert', path('root.pem'), '--key', path('other_key.pem'),
                                           '--not-after', not_after, '--out', out_file)
        expect(status.exitstatus).to eq(1)
        expect(stderr).to match(%r{ERROR: })
        expect(File.exist?(out_file)).to be(false)
      end
    end
  end
end
