# frozen_string_literal: true

require_relative '../unit_helper'
require 'openssl'
require 'tmpdir'
require 'time'
require_relative '../../../files/ca_reissue'

# Specs for the filesystem re-sign library (files/ca_reissue.rb).
#
# The fixture is a legacy Puppet CA: a self-signed root (serial 1) with pathlen:1, a
# critical custom extension and an authorityKeyIdentifier that names its issuer by
# DN and serial, and an intermediate issued by it with pathlen:0.
RSpec.describe CaExtend::Reissue do
  CUSTOM_CRITICAL_OID = '1.3.6.1.4.1.34380.99.1'
  CUSTOM_PLAIN_OID = '1.3.6.1.4.1.34380.99.2'

  let(:now) { Time.utc(2026, 11, 19, 12, 0, 0) }
  let(:far) { Time.utc(2041, 11, 19, 12, 0, 0) }

  let(:root_key) { CaExtendSpecKeys::ROOT }
  let(:int_key) { CaExtendSpecKeys::INTERMEDIATE }
  let(:other_key) { CaExtendSpecKeys::OTHER }

  def name(cn)
    OpenSSL::X509::Name.new([['CN', cn]])
  end

  def build_cert(subject:, issuer_cert:, key:, issuer_key:, serial:, not_before:, not_after:, extensions:)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = serial
    cert.subject = subject
    cert.issuer = issuer_cert ? issuer_cert.subject : subject
    cert.public_key = key.public_key
    cert.not_before = not_before
    cert.not_after = not_after
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = cert
    factory.issuer_certificate = issuer_cert || cert
    extensions.each { |oid, value, critical| cert.add_extension(make_extension(factory, oid, value, critical)) }
    cert.sign(issuer_key, OpenSSL::Digest.new('SHA256'))
    cert
  end

  # An ExtensionFactory only takes OIDs this OpenSSL has a name for (some builds refuse the
  # custom ones here), so a custom extension, given as `ASN1:UTF8String:text`, is built from DER.
  def make_extension(factory, oid, value, critical)
    return factory.create_extension(oid, value, critical) unless oid.match?(%r{\A\d+(\.\d+)+\z})

    text = value.delete_prefix('ASN1:UTF8String:')
    parts = [OpenSSL::ASN1::ObjectId.new(oid)]
    parts << OpenSSL::ASN1::Boolean.new(true) if critical # DER leaves out the default, FALSE
    parts << OpenSSL::ASN1::OctetString.new(OpenSSL::ASN1::UTF8String.new(text).to_der)
    OpenSSL::X509::Extension.new(OpenSSL::ASN1::Sequence.new(parts).to_der)
  end

  def legacy_root(aki: 'keyid,issuer:always', aki_critical: false, serial: 1, not_after: Time.utc(2027, 1, 1))
    build_cert(subject: name('Puppet CA: root'), issuer_cert: nil, key: root_key, issuer_key: root_key,
               serial: serial, not_before: Time.utc(2022, 1, 1), not_after: not_after,
               extensions: [['basicConstraints', 'CA:TRUE,pathlen:1', true],
                            ['keyUsage', 'keyCertSign,cRLSign', true],
                            ['subjectKeyIdentifier', 'hash', false],
                            ['authorityKeyIdentifier', aki, aki_critical],
                            [CUSTOM_CRITICAL_OID, 'ASN1:UTF8String:custom', true],
                            [CUSTOM_PLAIN_OID, 'ASN1:UTF8String:plain', false]])
  end

  def legacy_intermediate(root, serial: 2, not_after: Time.utc(2027, 1, 1))
    build_cert(subject: name('Puppet CA: intermediate'), issuer_cert: root, key: int_key, issuer_key: root_key,
               serial: serial, not_before: Time.utc(2022, 1, 1), not_after: not_after,
               extensions: [['basicConstraints', 'CA:TRUE,pathlen:0', true],
                            ['keyUsage', 'keyCertSign,cRLSign', false],
                            ['subjectKeyIdentifier', 'hash', false],
                            ['authorityKeyIdentifier', 'keyid,issuer:always', false],
                            [CUSTOM_PLAIN_OID, 'ASN1:UTF8String:int', false]])
  end

  def ext(cert, oid)
    cert.extensions.find { |e| e.oid == oid }
  end

  def ext_der(cert, oid)
    ext(cert, oid)&.to_der
  end

  # The AKI as OpenSSL itself builds the `keyid:always,issuer:always` form for `issuer`:
  # key id, the issuer certificate's own issuer DN and its serial. This is also the
  # form the CA-DB re-issue writes (puppetserver-private #620, `regenerated-aki`).
  def openssl_aki_der(issuer)
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.issuer_certificate = issuer
    factory.subject_certificate = issuer
    factory.create_extension('authorityKeyIdentifier', 'keyid:always,issuer:always', false).to_der
  end

  def aki_parts(cert)
    seq = OpenSSL::ASN1.decode(OpenSSL::ASN1.decode(ext_der(cert, 'authorityKeyIdentifier')).value.last.value)
    seq.value.each_with_object({}) { |el, h| h[el.tag] = el }
  end

  # The fixture root carries a critical custom extension that OpenSSL's path validation
  # does not know, so the store ignores unhandled critical extensions. It verifies at the
  # injected clock: the fixtures' own validity (to 2027) must not make the examples age out.
  def trust_store(root)
    store = OpenSSL::X509::Store.new
    store.flags = OpenSSL::X509::V_FLAG_IGNORE_CRITICAL
    store.time = now
    store.add_cert(root)
    store
  end

  def reissue(old, issuer: nil, key: root_key, not_after: far)
    described_class.reissue(old, issuer_cert: issuer, issuer_key: key, not_after: not_after, now: now)
  end

  describe 'a re-issued root' do
    let(:old) { legacy_root }
    let(:new) { reissue(old) }

    it 'keeps the subject, public key and subject key identifier' do
      expect(new.subject.to_der).to eq(old.subject.to_der)
      expect(new.public_key.to_der).to eq(old.public_key.to_der)
      expect(ext_der(new, 'subjectKeyIdentifier')).to eq(ext_der(old, 'subjectKeyIdentifier'))
    end

    it 'keeps the serial (the filesystem CA serial policy: extend.sh has always re-used it)' do
      expect(new.serial).to eq(old.serial)
      expect(new.serial).to eq(1)
    end

    it 'keeps the notBefore and takes the requested notAfter' do
      expect(new.not_before).to eq(old.not_before)
      expect(new.not_after).to eq(far)
    end

    it 'is a v3, SHA-256 certificate that verifies against its own key' do
      expect(new.version).to eq(2)
      expect(new.signature_algorithm).to eq('sha256WithRSAEncryption')
      expect(new.verify(root_key)).to be(true)
      expect(new.verify(root_key.public_key)).to be(true)
    end

    it 'copies every extension except the AKI byte for byte, in order, with criticality' do
      old_exts = old.extensions
      new_exts = new.extensions
      expect(new_exts.map(&:oid)).to eq(old_exts.map(&:oid))
      old_exts.zip(new_exts).each do |o, n|
        next if o.oid == 'authorityKeyIdentifier'

        expect(n.to_der).to eq(o.to_der), "extension #{o.oid} differs"
        expect(n.critical?).to eq(o.critical?)
      end
    end

    it 'keeps pathlen and the critical custom extension (what extend.sh used to drop)' do
      expect(ext(new, 'basicConstraints').value).to eq('CA:TRUE, pathlen:1')
      expect(ext(new, 'basicConstraints')).to be_critical
      expect(ext(new, 'keyUsage')).to be_critical
      expect(ext(new, CUSTOM_CRITICAL_OID)).to be_critical
      expect(ext_der(new, CUSTOM_CRITICAL_OID)).to eq(ext_der(old, CUSTOM_CRITICAL_OID))
    end

    it 'does not modify the certificate it was built from' do
      before = old.to_der
      new
      expect(old.to_der).to eq(before)
    end
  end

  describe 'the authorityKeyIdentifier' do
    it 'for a self-issued root names itself by key id, issuer DN and serial, as OpenSSL`s keyid:always,issuer:always does' do
      old = legacy_root
      new = reissue(old)
      expect(ext_der(new, 'authorityKeyIdentifier')).to eq(openssl_aki_der(new))
    end

    it 'for an intermediate names the re-issued root, the root`s own issuer DN and the root`s serial' do
      root = reissue(legacy_root(serial: 7))
      int = reissue(legacy_intermediate(legacy_root(serial: 7)), issuer: root)
      expect(ext_der(int, 'authorityKeyIdentifier')).to eq(openssl_aki_der(root))
      parts = aki_parts(int)
      expect(OpenSSL::BN.new(parts[2].value, 2).to_i).to eq(7)
    end

    it 'takes the issuer serial from the issuer it is signed under, not from the old AKI' do
      old_root = legacy_root(serial: 7)
      old_int = legacy_intermediate(old_root)
      new_root = reissue(legacy_root(serial: 9))
      int = reissue(old_int, issuer: new_root)
      expect(OpenSSL::BN.new(aki_parts(int)[2].value, 2).to_i).to eq(9)
      expect(ext_der(int, 'authorityKeyIdentifier')).to eq(openssl_aki_der(new_root))
    end

    it 'stays key-id only when the old AKI carried no issuer or serial' do
      old = legacy_root(aki: 'keyid:always')
      new = reissue(old)
      parts = aki_parts(new)
      expect(parts.keys).to eq([0])
      expect(parts[0].value).to eq(ext(new, 'subjectKeyIdentifier').value.delete(':').scan(%r{..}).map(&:hex).pack('C*'))
    end

    it 'does not add an AKI when the old certificate had none' do
      old = build_cert(subject: name('Puppet CA: root'), issuer_cert: nil, key: root_key, issuer_key: root_key,
                       serial: 1, not_before: Time.utc(2022, 1, 1), not_after: Time.utc(2027, 1, 1),
                       extensions: [['basicConstraints', 'CA:TRUE', true],
                                    ['subjectKeyIdentifier', 'hash', false]])
      expect(ext(reissue(old), 'authorityKeyIdentifier')).to be_nil
    end

    it "takes the key id from the issuer's own SKI even when that is not the hash of its key" do
      explicit = '01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67'
      root = build_cert(subject: name('Puppet CA: root'), issuer_cert: nil, key: root_key, issuer_key: root_key,
                        serial: 1, not_before: Time.utc(2022, 1, 1), not_after: Time.utc(2027, 1, 1),
                        extensions: [['basicConstraints', 'CA:TRUE,pathlen:1', true],
                                     ['subjectKeyIdentifier', explicit, false],
                                     ['authorityKeyIdentifier', 'keyid', false]])
      parts = OpenSSL::ASN1.decode(OpenSSL::ASN1.decode(ext(reissue(root), 'authorityKeyIdentifier').to_der).value.last.value).value
      key_id = parts.first.value
      expect(key_id.unpack('H*').first).to eq(explicit.delete(':'))
      expect(key_id).not_to eq(OpenSSL::Digest.new('SHA1').digest(OpenSSL::ASN1.decode(root_key.public_key.to_der).value[1].value))
    end

    it 'hashes the issuer`s public key for the key id when the issuer has no subject key identifier' do
      aki = OpenSSL::X509::Extension.new(
        OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId.new('authorityKeyIdentifier'),
                                     OpenSSL::ASN1::OctetString.new(described_class.aki_der('x' * 20, nil, nil))]).to_der,
      )
      old = legacy_root
      old.extensions = [ext(old, 'basicConstraints'), aki]
      old.sign(root_key, OpenSSL::Digest.new('SHA256'))
      factory = OpenSSL::X509::ExtensionFactory.new
      factory.subject_certificate = legacy_root
      expected = OpenSSL::ASN1.decode(OpenSSL::ASN1.decode(factory.create_extension('subjectKeyIdentifier', 'hash').to_der).value.last.value).value
      expect(aki_parts(reissue(old))[0].value).to eq(expected)
    end

    it 'keeps the criticality of the old AKI, critical or not' do
      [true, false].each do |critical|
        old = legacy_root(aki_critical: critical)
        expect(ext(old, 'authorityKeyIdentifier').critical?).to eq(critical)
        expect(ext(reissue(old), 'authorityKeyIdentifier').critical?).to eq(critical)
      end
    end

    # Every other signer in these examples is a self-signed root, whose issuer DN is its
    # own subject. Here the issuer was itself issued by someone else, so the AKI must name
    # the issuer`s ISSUER (the root), not the issuer.
    it 'names the issuer`s own issuer DN, not the issuer`s subject, when the issuer is not self-signed' do
      root = legacy_root
      sub_ca = build_cert(subject: OpenSSL::X509::Name.new([['O', 'Puppet'], ['CN', 'Puppet CA: sub'], ['OU', 'Support']]),
                          issuer_cert: root, key: int_key, issuer_key: root_key, serial: 5,
                          not_before: Time.utc(2022, 1, 1), not_after: Time.utc(2027, 1, 1),
                          extensions: [['basicConstraints', 'CA:TRUE,pathlen:0', true],
                                       ['subjectKeyIdentifier', 'hash', false],
                                       ['authorityKeyIdentifier', 'keyid:always,issuer:always', false]])
      leaf_ca = build_cert(subject: name('Puppet CA: leaf'), issuer_cert: sub_ca, key: other_key, issuer_key: int_key,
                           serial: 6, not_before: Time.utc(2022, 1, 1), not_after: Time.utc(2026, 12, 1),
                           extensions: [['basicConstraints', 'CA:TRUE', true],
                                        ['subjectKeyIdentifier', 'hash', false],
                                        ['authorityKeyIdentifier', 'keyid:always,issuer:always', false]])
      new = reissue(leaf_ca, issuer: sub_ca, key: int_key, not_after: Time.utc(2026, 12, 2))
      issuer_dn = OpenSSL::ASN1.decode(aki_parts(new)[1].value.first.value.first.to_der).to_der
      expect(issuer_dn).to eq(root.subject.to_der)
      expect(issuer_dn).not_to eq(sub_ca.subject.to_der)
      expect(OpenSSL::BN.new(aki_parts(new)[2].value, 2).to_i).to eq(5)
      expect(ext_der(new, 'authorityKeyIdentifier')).to eq(openssl_aki_der(sub_ca))
    end

    # Golden values produced with BouncyCastle, the library the CA-DB re-issue uses:
    #   new AuthorityKeyIdentifier(keyId, new GeneralNames(new GeneralName(new X500Name("CN=Puppet CA: root"))), serial)
    # for key id 01..14 (hex) and serial 7, and for serial 0xff00000000000001.
    # `new AuthorityKeyIdentifier(keyId)` gives the key-id-only form.
    describe '.aki_der against the CA-DB (puppetserver-private #620, BouncyCastle) encoding' do
      let(:key_id) { (1..20).to_a.pack('C*') }
      let(:dn) { OpenSSL::X509::Name.new([['CN', 'Puppet CA: root']]) }

      it 'matches for a small serial' do
        expect(described_class.aki_der(key_id, dn, OpenSSL::BN.new(7)).unpack1('H*'))
          .to eq('303980140102030405060708090a0b0c0d0e0f1011121314a11ea41c301a3118301606035504030c0f5075707065742043413a20726f6f74820107')
      end

      it 'matches for a serial whose top bit is set' do
        expect(described_class.aki_der(key_id, dn, OpenSSL::BN.new('ff00000000000001', 16)).unpack1('H*'))
          .to eq('304180140102030405060708090a0b0c0d0e0f1011121314a11ea41c301a3118301606035504030c0f5075707065742043413a20726f6f74820900ff00000000000001')
      end

      it 'matches for the key-id-only form' do
        expect(described_class.aki_der(key_id, nil, nil).unpack1('H*'))
          .to eq('301680140102030405060708090a0b0c0d0e0f1011121314')
      end
    end
  end

  describe 'a re-issued intermediate' do
    let(:old_root) { legacy_root }
    let(:old_int) { legacy_intermediate(old_root) }
    let(:new_root) { reissue(old_root) }
    let(:new_int) { reissue(old_int, issuer: new_root) }

    it 'is issued by the re-issued root and verifies against it' do
      expect(new_int.issuer.to_der).to eq(new_root.subject.to_der)
      expect(new_int.verify(new_root.public_key)).to be(true)
      expect(new_int.verify(int_key.public_key)).to be(false)
    end

    it 'keeps subject, key, serial, notBefore and every other extension byte for byte' do
      expect(new_int.subject.to_der).to eq(old_int.subject.to_der)
      expect(new_int.public_key.to_der).to eq(old_int.public_key.to_der)
      expect(new_int.serial).to eq(old_int.serial)
      expect(new_int.not_before).to eq(old_int.not_before)
      expect(ext(new_int, 'basicConstraints').value).to eq('CA:TRUE, pathlen:0')
      (old_int.extensions.map(&:oid) - ['authorityKeyIdentifier']).each do |oid|
        expect(ext_der(new_int, oid)).to eq(ext_der(old_int, oid))
      end
      expect(new_int.extensions.map(&:oid)).to eq(old_int.extensions.map(&:oid))
    end

    # The root keeps its serial, so the serial-bound AKI still names it: OpenSSL
    # accepts the re-issued root as the intermediate's issuer.
    it 'chains to the re-issued root through OpenSSL path validation, serial-bound AKI included' do
      store = trust_store(new_root)
      expect(store.verify(new_int)).to be(true), store.error_string
    end

    it 'still chains to the old root, whose serial the AKI names (same key, same serial)' do
      store = trust_store(old_root)
      expect(store.verify(new_int)).to be(true), store.error_string
    end
  end

  describe 'refusals' do
    let(:old) { legacy_root }

    it 'refuses a notAfter that is not in the future' do
      expect { reissue(old, not_after: now - 1) }
        .to raise_error(described_class::Error, %r{must lie in the future})
    end

    it 'refuses a notAfter further than 36500 days ahead' do
      expect { reissue(old, not_after: now + (36_500 * 86_400) + 1) }
        .to raise_error(described_class::Error, %r{at most 36500 days})
    end

    it 'accepts a notAfter exactly 36500 days ahead' do
      expect(reissue(old, not_after: now + (36_500 * 86_400)).not_after).to eq(now + (36_500 * 86_400))
    end

    it 'refuses a notAfter that is not later than the current one' do
      expect { reissue(old, not_after: old.not_after) }
        .to raise_error(described_class::Error, %r{not later than the current})
      expect { reissue(old, not_after: old.not_after - 60) }
        .to raise_error(described_class::Error, %r{not later than the current})
    end

    it 'refuses a notAfter later than the issuer`s and says to extend the root first' do
      root = reissue(legacy_root, not_after: Time.utc(2030, 1, 1))
      expect { reissue(legacy_intermediate(legacy_root), issuer: root, not_after: Time.utc(2031, 1, 1)) }
        .to raise_error(described_class::Error, %r{later than the issuer.*extend the root first})
    end

    it 'accepts a notAfter equal to the issuer`s' do
      root = reissue(legacy_root, not_after: far)
      expect(reissue(legacy_intermediate(legacy_root), issuer: root, not_after: far).not_after).to eq(far)
    end

    it 'refuses a signing key that does not match the issuing certificate' do
      expect { reissue(old, key: other_key) }
        .to raise_error(described_class::Error, %r{does not match the issuing certificate})
      root = reissue(legacy_root)
      expect { reissue(legacy_intermediate(legacy_root), issuer: root, key: int_key) }
        .to raise_error(described_class::Error, %r{does not match the issuing certificate})
    end

    it 'refuses a certificate that is not self-issued when no issuer certificate is given' do
      intermediate = legacy_intermediate(legacy_root)
      expect { reissue(intermediate, key: int_key) }
        .to raise_error(described_class::Error, %r{not self-issued.*issuer certificate is needed})
    end

    # The re-issued certificate is stamped with the given issuer's subject, so an issuer
    # certificate that did not issue the old one would silently re-parent it.
    it 'refuses an issuer certificate that is not the one that issued the old certificate' do
      intermediate = legacy_intermediate(legacy_root)
      unrelated = OpenSSL::X509::Certificate.new(reissue(legacy_root).to_der)
      unrelated.subject = OpenSSL::X509::Name.new([['CN', 'Some other CA']])
      unrelated.sign(root_key, OpenSSL::Digest.new('SHA256'))
      expect { reissue(intermediate, issuer: unrelated, key: root_key) }
        .to raise_error(described_class::Error, %r{was issued by .*not by the given issuer certificate .*Some other CA})
    end

    it 'truncates a notAfter with fractional seconds to whole seconds' do
      expect(reissue(old, not_after: far + 0.75).not_after).to eq(far)
    end
  end

  describe 'a certificate with a malformed identifier extension' do
    # An extension whose extnValue is `value_der`, put in place of the certificate's own.
    def with_extension(cert, oid, value_der)
      copy = OpenSSL::X509::Certificate.new(cert.to_der)
      broken = OpenSSL::X509::Extension.new(
        OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId.new(oid), OpenSSL::ASN1::OctetString.new(value_der)]).to_der,
      )
      copy.extensions = copy.extensions.map { |e| (e.oid == oid) ? broken : e }
      copy.sign(root_key, OpenSSL::Digest.new('SHA256'))
      copy
    end

    it 'refuses an AKI that is not a SEQUENCE, as an Error rather than a NoMethodError' do
      old = with_extension(legacy_root, 'authorityKeyIdentifier', "\x04\x01\x00".b)
      expect { reissue(old) }.to raise_error(described_class::Error, %r{authorityKeyIdentifier is not a SEQUENCE})
    end

    it 'refuses an SKI that is not an OCTET STRING, as an Error rather than a TypeError' do
      old = with_extension(legacy_root, 'subjectKeyIdentifier', "\x02\x01\x05".b)
      expect { reissue(old) }.to raise_error(described_class::Error, %r{subjectKeyIdentifier of .* is not an OCTET STRING})
    end

    it 'refuses an SKI with an empty key identifier, rather than writing an AKI with an empty key id' do
      old = with_extension(legacy_root, 'subjectKeyIdentifier', "\x04\x00".b)
      expect { reissue(old) }.to raise_error(described_class::Error, %r{subjectKeyIdentifier of .* is empty})
    end

    it 'refuses an SKI that is an empty SEQUENCE, rather than writing a garbage AKI' do
      old = with_extension(legacy_root, 'subjectKeyIdentifier', "\x30\x00".b)
      expect { reissue(old) }.to raise_error(described_class::Error, %r{subjectKeyIdentifier of .* is not an OCTET STRING})
    end
  end

  # A root that already outlives the requested notAfter cannot be "extended" (the re-issue is
  # refused as not later), but it is sufficient: it is kept so the intermediate can be renewed.
  describe '.keep_if_sufficient' do
    let(:long_root) { legacy_root(not_after: Time.utc(2051, 1, 1)) }

    def keep(old, issuer: nil, key: root_key, not_after: far)
      described_class.keep_if_sufficient(old, issuer_cert: issuer, issuer_key: key, not_after: not_after, now: now)
    end

    it 'returns the certificate itself when it expires later than the requested notAfter' do
      expect(keep(long_root)).to equal(long_root)
    end

    it 'returns the certificate itself when it expires exactly at the requested notAfter' do
      expect(keep(legacy_root(not_after: far))).not_to be_nil
    end

    it 'returns nil when the certificate expires before the requested notAfter, so it must be re-issued' do
      expect(keep(legacy_root)).to be_nil
    end

    it 'still refuses a signing key that does not match' do
      expect { keep(long_root, key: other_key) }
        .to raise_error(described_class::Error, %r{does not match the issuing certificate})
    end

    it 'still refuses a requested notAfter that is not in the future or too far ahead' do
      expect { keep(long_root, not_after: now - 1) }.to raise_error(described_class::Error, %r{must lie in the future})
      expect { keep(legacy_root(not_after: Time.utc(2130, 1, 1)), not_after: now + (36_500 * 86_400) + 1) }
        .to raise_error(described_class::Error, %r{at most 36500 days})
    end

    it 'refuses a certificate that its issuer did not sign, rather than keeping it' do
      forged = OpenSSL::X509::Certificate.new(long_root.to_der)
      forged.sign(other_key, OpenSSL::Digest.new('SHA256'))
      expect { keep(forged) }.to raise_error(described_class::Error, %r{is not signed by .*refusing to keep it})
    end

    it 'refuses, with the same message, a certificate signed with a different key type than its issuer has' do
      forged = OpenSSL::X509::Certificate.new(long_root.to_der)
      forged.sign(OpenSSL::PKey::EC.generate('prime256v1'), OpenSSL::Digest.new('SHA256'))
      expect { keep(forged) }.to raise_error(described_class::Error, %r{is not signed by .*refusing to keep it})
    end

    it 'still refuses an issuer certificate that did not issue the certificate' do
      unrelated = OpenSSL::X509::Certificate.new(long_root.to_der)
      unrelated.subject = OpenSSL::X509::Name.new([['CN', 'Some other CA']])
      unrelated.sign(root_key, OpenSSL::Digest.new('SHA256'))
      intermediate = legacy_intermediate(legacy_root, not_after: Time.utc(2051, 1, 1))
      expect { keep(intermediate, issuer: unrelated) }
        .to raise_error(described_class::Error, %r{was issued by .*not by the given issuer certificate})
    end
  end

  describe '.parse_time' do
    it 'reads an ISO 8601 time' do
      expect(described_class.parse_time('2041-11-19T12:00:00Z')).to eq(far)
    end

    it 'reads the UTCTime form (YYMMDDHHMMSSZ)' do
      expect(described_class.parse_time('411119120000Z')).to eq(far)
    end

    it 'reads a two-digit year of 50 or more as 19YY, as RFC 5280 does' do
      expect(described_class.parse_time('500101000000Z')).to eq(Time.utc(1950, 1, 1))
    end

    it 'rejects a time that matches the form but is not a calendar time, rather than rolling it over' do
      ['2041-13-45T00:00:00Z', '2041-11-19T25:00:00Z', '2041-02-30T00:00:00Z', '411332000000Z', '410230000000Z'].each do |text|
        expect { described_class.parse_time(text) }.to raise_error(described_class::Error, %r{not a time})
      end
    end

    it 'rejects an offset that matches the form but that Ruby refuses, as a plain error' do
      expect { described_class.parse_time('2041-11-19T12:00:00+99:99') }.to raise_error(described_class::Error, %r{not a time})
    end

    it 'rejects anything else' do
      expect { described_class.parse_time('next year') }.to raise_error(described_class::Error, %r{not a time})
      expect { described_class.parse_time('') }.to raise_error(described_class::Error, %r{not a time})
    end
  end
end
