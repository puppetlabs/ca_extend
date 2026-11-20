# frozen_string_literal: true

# Run on the target with PE's Ruby by spec/acceptance/tasks/extend_ca_cert_spec.rb:
#
#   compare_ca_bundles.rb OLD_BUNDLE.pem NEW_BUNDLE.pem [REQUESTED_NOT_AFTER]
#
# With REQUESTED_NOT_AFTER (an ISO 8601 time), a certificate carried over byte for byte is accepted
# when it already expires no earlier than that (extend.sh keeps such a certificate as it is);
# without it, every certificate must have a later notAfter.
#
# Prints a JSON array with one string per way the extended bundle differs from the old one
# in what an extension must preserve or keep valid (empty when nothing differs). Certificates are
# matched by subject.
require 'json'
require 'openssl'
require 'time'

def certs(path)
  File.read(path).scan(%r{-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----}m)
      .map { |pem| OpenSSL::X509::Certificate.new(pem) }
end

# These helpers deliberately do not use files/ca_reissue.rb: the script checks that code's
# output, so it must not trust it.
def ext_value_der(ext)
  OpenSSL::ASN1.decode(ext.to_der).value.last.value
end

def aki_key_id(cert)
  ext = cert.extensions.find { |e| e.oid == 'authorityKeyIdentifier' }
  return unless ext

  el = OpenSSL::ASN1.decode(ext_value_der(ext)).value.find { |v| v.tag_class == :CONTEXT_SPECIFIC && v.tag.zero? }
  el&.value
end

# The AKI's [1] authorityCertIssuer directoryName (DER of the Name) and [2] serial, nil when absent.
def aki_authority(cert)
  ext = cert.extensions.find { |e| e.oid == 'authorityKeyIdentifier' }
  return [nil, nil] unless ext

  parts = OpenSSL::ASN1.decode(ext_value_der(ext)).value.select { |v| v.tag_class == :CONTEXT_SPECIFIC }
  names = parts.find { |v| v.tag == 1 }
  serial = parts.find { |v| v.tag == 2 }
  [names && names.value.first.value.first.to_der, serial && OpenSSL::BN.new(serial.value, 2)]
end

def aki?(cert)
  cert.extensions.any? { |e| e.oid == 'authorityKeyIdentifier' }
end

# The key id an AKI naming `cert` should carry: its SKI, else the SHA-1 of its subjectPublicKey
# (what a `subjectKeyIdentifier=hash` SKI would have been).
def ski(cert)
  ext = cert.extensions.find { |e| e.oid == 'subjectKeyIdentifier' }
  return OpenSSL::ASN1.decode(ext_value_der(ext)).value if ext

  OpenSSL::Digest.new('SHA1').digest(OpenSSL::ASN1.decode(cert.public_key.to_der).value[1].value)
end

old_certs, new_certs = ARGV.first(2).map { |path| certs(path) }
requested = ARGV[2] && Time.iso8601(ARGV[2])
problems = []
problems << 'the old bundle holds no certificates' if old_certs.empty?
problems << "old bundle has #{old_certs.size} certificate(s), new has #{new_certs.size}" unless old_certs.size == new_certs.size

old_certs.each do |old|
  label = old.subject.to_s
  new = new_certs.find { |c| c.subject.to_der == old.subject.to_der }
  unless new
    problems << "#{label}: missing from the new bundle"
    next
  end
  problems << "#{label}: version changed (#{old.version} -> #{new.version})" unless new.version == old.version
  problems << "#{label}: public key changed" unless new.public_key.to_der == old.public_key.to_der
  problems << "#{label}: serial changed (#{old.serial} -> #{new.serial})" unless new.serial == old.serial
  problems << "#{label}: notBefore changed" unless new.not_before == old.not_before
  kept = requested && new.to_der == old.to_der && new.not_after >= requested
  problems << "#{label}: notAfter not later" unless kept || new.not_after > old.not_after
  problems << "#{label}: extensions differ in OID or order" unless new.extensions.map(&:oid) == old.extensions.map(&:oid)
  old.extensions.zip(new.extensions).each do |o, n|
    next if n.nil?

    # The AKI's value is rebuilt from the issuer (checked below), but its criticality is kept.
    if o.oid == 'authorityKeyIdentifier'
      problems << "#{label}: AKI criticality changed" unless n.critical? == o.critical?
      next
    end

    problems << "#{label}: extension #{o.oid} is not byte for byte the old one" unless n.to_der == o.to_der
  end
  issuer = new_certs.find { |c| c.subject.to_der == new.issuer.to_der }
  problems << "#{label}: issuer is not in the new bundle" unless issuer
  problems << "#{label}: signature does not verify against its issuer" if issuer && !new.verify(issuer.public_key)
  problems << "#{label}: AKI key id is not the issuer's SKI" if issuer && aki?(new) && aki_key_id(new) != ski(issuer)
  problems << "#{label}: AKI appeared or disappeared" unless aki?(old) == aki?(new)
  old_names, old_serial = aki_authority(old)
  new_names, new_serial = aki_authority(new)
  unless old_names.nil? == new_names.nil? && old_serial.nil? == new_serial.nil?
    problems << "#{label}: AKI form changed (authority issuer and serial present before: " \
                "#{!old_names.nil?}/#{!old_serial.nil?}, now: #{!new_names.nil?}/#{!new_serial.nil?})"
  end
  if issuer && new_names && new_names != issuer.issuer.to_der
    problems << "#{label}: AKI authority issuer is not the issuer's issuer"
  end
  problems << "#{label}: AKI authority serial is not the issuer's" if issuer && new_serial && new_serial != issuer.serial
end

puts JSON.generate(problems)
