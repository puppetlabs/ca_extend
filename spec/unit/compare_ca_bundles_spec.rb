# frozen_string_literal: true

require_relative 'unit_helper'
require 'fileutils'
require 'json'
require 'open3'
require 'openssl'
require 'rbconfig'
require 'tmpdir'
require_relative '../../files/ca_reissue'

# The Litmus acceptance spec trusts spec/acceptance/support/compare_ca_bundles.rb to say
# whether an extended bundle kept what it must, and Litmus is the only place it runs. These
# examples run it on a root + intermediate bundle, the shape Litmus gives it: a faithful
# re-issue must report nothing, and each check must report when what it guards is broken, so a
# script that always printed [] (or lost a check) fails here.
RSpec.describe 'spec/acceptance/support/compare_ca_bundles.rb' do
  let(:script) { File.expand_path('../acceptance/support/compare_ca_bundles.rb', __dir__) }
  let(:dir) { Dir.mktmpdir('compare_ca_bundles') }
  let(:root_key) { CaExtendSpecKeys::ROOT }
  let(:int_key) { CaExtendSpecKeys::INTERMEDIATE }
  let(:other_key) { CaExtendSpecKeys::OTHER }
  let(:not_after) { Time.now + (10 * 365 * 86_400) }
  let(:old_root) { make_cert('Puppet CA: root', root_key, root_key, nil, 1, 'CA:TRUE,pathlen:1') }
  let(:old_int) { make_cert('Puppet CA: intermediate', int_key, root_key, old_root, 2, 'CA:TRUE,pathlen:0') }
  let(:new_root) { CaExtend::Reissue.reissue(old_root, issuer_cert: nil, issuer_key: root_key, not_after: not_after) }
  let(:new_int) { CaExtend::Reissue.reissue(old_int, issuer_cert: new_root, issuer_key: root_key, not_after: not_after) }

  after(:each) { FileUtils.remove_entry(dir) }

  def make_cert(cn, key, issuer_key, issuer, serial, constraints, ski: true)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = serial
    cert.subject = OpenSSL::X509::Name.new([['CN', cn]])
    cert.issuer = issuer ? issuer.subject : cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now - (365 * 86_400)
    cert.not_after = Time.now + (30 * 86_400)
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = cert
    factory.issuer_certificate = issuer || cert
    cert.add_extension(factory.create_extension('basicConstraints', constraints, true))
    cert.add_extension(factory.create_extension('subjectKeyIdentifier', 'hash', false)) if ski
    cert.add_extension(factory.create_extension('authorityKeyIdentifier', 'keyid:always,issuer:always', false)) if ski
    cert.sign(issuer_key, OpenSSL::Digest.new('SHA256'))
    cert
  end

  # Changes the certificate (a block) and signs it again, as a broken extension would.
  def tampered(cert, signing_key = root_key)
    copy = OpenSSL::X509::Certificate.new(cert.to_der)
    yield copy
    copy.sign(signing_key, OpenSSL::Digest.new('SHA256'))
    copy
  end

  def aki_with_key_id(key_id)
    der = OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ASN1Data.new(key_id, 0, :CONTEXT_SPECIFIC)]).to_der
    oid = OpenSSL::ASN1::ObjectId.new('authorityKeyIdentifier')
    OpenSSL::X509::Extension.new(OpenSSL::ASN1::Sequence.new([oid, OpenSSL::ASN1::OctetString.new(der)]).to_der)
  end

  def problems(old_certs, new_certs, *requested)
    File.write(File.join(dir, 'old.pem'), old_certs.map(&:to_pem).join)
    File.write(File.join(dir, 'new.pem'), new_certs.map(&:to_pem).join)
    out, err, status = Open3.capture3(RbConfig.ruby, script, File.join(dir, 'old.pem'), File.join(dir, 'new.pem'), *requested)
    expect(status.exitstatus).to eq(0), err
    JSON.parse(out)
  end

  def int_problems(&change)
    problems([old_root, old_int], [new_root, tampered(new_int, &change)]).join("\n")
  end

  it 'reports nothing for a faithful re-issue of a root and its intermediate' do
    expect(problems([old_root, old_int], [new_root, new_int])).to eq([])
  end

  it 'reports a dropped pathlen' do
    out = int_problems do |c|
      c.extensions = c.extensions.map do |e|
        (e.oid == 'basicConstraints') ? OpenSSL::X509::Extension.new('basicConstraints', 'CA:TRUE', true) : e
      end
    end
    expect(out).to match(%r{intermediate: extension basicConstraints is not byte for byte})
  end

  it 'reports a changed serial' do
    expect(int_problems { |c| c.serial = 99 }).to match(%r{intermediate: serial changed})
  end

  # OpenSSL makes a certificate with extensions v3 whatever is set, so the version example
  # uses certificates without extensions.
  it 'reports a changed X.509 version' do
    bare = ->(version) do
      cert = OpenSSL::X509::Certificate.new
      cert.version = version
      cert.serial = 1
      cert.subject = cert.issuer = OpenSSL::X509::Name.new([['CN', 'Puppet CA: root']])
      cert.public_key = root_key.public_key
      cert.not_before = old_root.not_before
      cert.not_after = old_root.not_after
      cert.sign(root_key, OpenSSL::Digest.new('SHA256'))
      cert
    end
    expect(problems([bare.call(0)], [bare.call(2)]).join("\n")).to match(%r{root: version changed \(0 -> 2\)})
  end

  it 'reports a changed public key' do
    expect(int_problems { |c| c.public_key = other_key.public_key }).to match(%r{intermediate: public key changed})
  end

  it 'reports a changed notBefore' do
    expect(int_problems { |c| c.not_before = old_int.not_before - 86_400 }).to match(%r{intermediate: notBefore changed})
  end

  it 'reports a notAfter that is not later' do
    expect(int_problems { |c| c.not_after = old_int.not_after }).to match(%r{intermediate: notAfter not later})
  end

  context 'with the requested end date (a certificate that already outlives it is kept)' do
    let(:requested) { (Time.now + (10 * 365 * 86_400)).utc.iso8601 }
    let(:long_root) { tampered(old_root) { |c| c.not_after = Time.now + (20 * 365 * 86_400) } }
    let(:renewed_int) do
      CaExtend::Reissue.reissue(old_int, issuer_cert: long_root, issuer_key: root_key, not_after: Time.parse(requested))
    end

    it 'accepts a root kept unchanged that expires after the requested date, with a renewed intermediate' do
      expect(problems([long_root, old_int], [long_root, renewed_int], requested)).to eq([])
    end

    it 'still reports an unchanged certificate that expires before the requested date' do
      expect(problems([old_root, old_int], [old_root, new_int], requested).join("\n")).to match(%r{root: notAfter not later})
    end

    it 'still reports an unchanged certificate when no requested date is given' do
      expect(problems([long_root, old_int], [long_root, renewed_int]).join("\n")).to match(%r{root: notAfter not later})
    end

    it 'does not accept a changed certificate as kept just because it expires after the requested date' do
      changed = tampered(long_root) { |c| c.not_before = c.not_before + 1 }
      expect(problems([long_root, old_int], [changed, renewed_int], requested).join("\n")).to match(%r{root: notAfter not later})
    end
  end

  it 'reports extensions in a different order' do
    expect(int_problems { |c| c.extensions = c.extensions.reverse }).to match(%r{intermediate: extensions differ in OID or order})
  end

  it 'reports a signature that does not verify against the issuer' do
    out = problems([old_root, old_int], [new_root, tampered(new_int, other_key) { |_c| }]).join("\n")
    expect(out).to match(%r{intermediate: signature does not verify against its issuer})
  end

  it "reports an AKI key id that is not the issuer's SKI" do
    out = int_problems do |c|
      c.extensions = c.extensions.map { |e| (e.oid == 'authorityKeyIdentifier') ? aki_with_key_id("\x01".b * 20) : e }
    end
    expect(out).to match(%r{intermediate: AKI key id is not the issuer's SKI})
  end

  def aki_with_authority(key_id, issuer_name, serial)
    der = CaExtend::Reissue.aki_der(key_id, issuer_name, serial)
    oid = OpenSSL::ASN1::ObjectId.new('authorityKeyIdentifier')
    OpenSSL::X509::Extension.new(OpenSSL::ASN1::Sequence.new([oid, OpenSSL::ASN1::OctetString.new(der)]).to_der)
  end

  def root_ski
    OpenSSL::ASN1.decode(OpenSSL::ASN1.decode(new_root.extensions.find { |e| e.oid == 'subjectKeyIdentifier' }.to_der).value.last.value).value
  end

  def int_with_aki(aki)
    int_problems { |c| c.extensions = c.extensions.map { |e| (e.oid == 'authorityKeyIdentifier') ? aki : e } }
  end

  it "reports an AKI whose authority serial is not the issuer's although the key id is right" do
    out = int_with_aki(aki_with_authority(root_ski, new_root.issuer, 99))
    expect(out).to match(%r{intermediate: AKI authority serial is not the issuer's})
  end

  it "reports an AKI whose authority issuer name is not the issuer's issuer although the key id is right" do
    out = int_with_aki(aki_with_authority(root_ski, OpenSSL::X509::Name.new([['CN', 'Elsewhere']]), new_root.serial))
    expect(out).to match(%r{intermediate: AKI authority issuer is not the issuer's issuer})
  end

  it 'reports an AKI that lost the authority issuer and serial the old one carried' do
    out = int_with_aki(aki_with_key_id(root_ski))
    expect(out).to match(%r{intermediate: AKI form changed})
  end

  def critical(extension)
    parts = OpenSSL::ASN1.decode(extension.to_der).value
    seq = OpenSSL::ASN1::Sequence.new([parts.first, OpenSSL::ASN1::Boolean.new(true), parts.last])
    OpenSSL::X509::Extension.new(seq.to_der)
  end

  it 'reports an AKI whose criticality changed' do
    out = int_problems do |c|
      c.extensions = c.extensions.map { |e| (e.oid == 'authorityKeyIdentifier') ? critical(e) : e }
    end
    expect(out).to match(%r{intermediate: AKI criticality changed})
  end

  # The re-issue falls back to the SHA-1 of the issuer's public key when the issuer has no SKI,
  # which is what `subjectKeyIdentifier=hash` would have been: the comparator must accept it.
  it 'reports nothing for a faithful re-issue under an issuer without a subjectKeyIdentifier' do
    bare_root = make_cert('Puppet CA: root', root_key, root_key, nil, 1, 'CA:TRUE,pathlen:1', ski: false)
    expect(bare_root.extensions.map(&:oid)).not_to include('subjectKeyIdentifier')
    new_bare = CaExtend::Reissue.reissue(bare_root, issuer_cert: nil, issuer_key: root_key, not_after: not_after)
    new_child = CaExtend::Reissue.reissue(old_int, issuer_cert: new_bare, issuer_key: root_key, not_after: not_after)
    expect(problems([bare_root, old_int], [new_bare, new_child])).to eq([])
  end

  it 'reports an AKI that disappeared' do
    out = int_problems { |c| c.extensions = c.extensions.reject { |e| e.oid == 'authorityKeyIdentifier' } }
    expect(out).to match(%r{intermediate: AKI appeared or disappeared})
  end

  it 'reports a certificate missing from the new bundle, and an intermediate whose issuer is gone' do
    out = problems([old_root, old_int], [new_int]).join("\n")
    expect(out).to match(%r{root: missing from the new bundle})
    expect(out).to match(%r{intermediate: issuer is not in the new bundle})
  end

  it 'reports a different number of certificates' do
    expect(problems([old_root, old_int], [new_root, new_int, new_int]).join("\n"))
      .to match(%r{old bundle has 2 certificate\(s\), new has 3})
  end

  it 'does not pass vacuously on an empty bundle' do
    expect(problems([], []).join("\n")).to match(%r{old bundle holds no certificates})
  end
end
