# frozen_string_literal: true

require 'openssl'
require 'date'
require 'time'

# rubocop:disable Style/ClassAndModuleChildren
# (The CaExtend namespace is shared with files/extend_cert.rb, so it is not written compactly.)
module CaExtend
  # Re-issues a CA certificate for the filesystem backend: the same subject, public key,
  # serial and notBefore, a later notAfter, every extension copied byte for byte except the
  # authorityKeyIdentifier, which is rebuilt from the issuer.
  #
  # This replaces the `openssl x509 -x509toreq` + `openssl ca` re-sign that extend.sh used,
  # which rewrote the extensions from a fixed config (dropping pathlen, the criticality of
  # keyUsage and any custom extension) and wrote a key-id-only AKI.
  #
  # The rules follow the CA-DB re-issue (puppetserver-private PE-48305, `ca/extend.clj`):
  #
  # * notAfter must lie in (now, now + 36500 days], be later than the certificate's current
  #   notAfter, and not be later than the issuer's notAfter;
  # * the AKI carries the issuer's key id and, only if the old AKI named its authority by
  #   issuer DN and serial (as older Puppet CAs do), the issuer certificate's own issuer DN
  #   and serial. For a self-signed root the issuer is the certificate itself;
  # * the notBefore is the old certificate's.
  #
  # `keep_if_sufficient` waives the first rule's "later than current" and "not later than the
  # issuer's" parts for a certificate that already expires no earlier than the new notAfter.
  #
  # One deliberate difference: the CA-DB re-issue takes a new serial from the CA's counter
  # (the old certificate is kept beside the new one, so it needs its own); this helper keeps
  # the old serial, as extend.sh always has. A serial-bound AKI on a signer or ICA names the
  # root by serial, so a root that kept its serial still chains for them, and extending only
  # the root leaves nothing stranded on the filesystem backend.
  #
  # Written to run on every Ruby PE ships (2.5 and later): no syntax or methods newer than that.
  module Reissue
    class Error < StandardError; end

    # The furthest a notAfter may lie in the future, as in the CA-DB re-issue.
    MAX_EXTENSION_DAYS = 36_500
    AKI = 'authorityKeyIdentifier'
    SKI = 'subjectKeyIdentifier'

    module_function

    # Returns the re-issued OpenSSL::X509::Certificate for `old`, signed with `issuer_key`.
    # `issuer_cert` is the issuer's certificate, nil when `old` is self-signed; when given, its
    # subject must be `old`'s issuer name. Raises Error, and returns nothing, if `old` is
    # not self-issued and no issuer certificate is given, if the given issuer certificate's
    # subject is not `old`'s issuer, if the key does not belong to the issuer, if the notAfter
    # is refused, or if an AKI or SKI involved is malformed.
    def reissue(old, issuer_cert:, issuer_key:, not_after:, now: Time.now)
      signer = issuer_cert || old
      check_issuer_given!(old, issuer_cert)
      not_after = Time.at(not_after.to_i).utc
      check_key!(signer, issuer_key)
      check_not_after!(not_after, old, issuer_cert, now)

      cert = OpenSSL::X509::Certificate.new
      # X.509 v3; an older OpenSSL leaves a fresh certificate at v1, which cannot carry extensions.
      cert.version = 2
      cert.serial = old.serial
      cert.subject = old.subject
      cert.issuer = signer.subject
      cert.public_key = old.public_key
      cert.not_before = old.not_before
      cert.not_after = not_after
      old.extensions.each do |extension|
        cert.add_extension(reissued_extension(extension, signer))
      end
      cert.sign(issuer_key, OpenSSL::Digest.new('SHA256'))
      cert
    end

    # Returns `old` itself, unchanged, when it already expires no earlier than `not_after`: a
    # re-issue would be refused as not later, but nothing is missing, so the caller can keep it
    # (a root that outlives the new expiry must not block renewing its intermediate). Returns
    # nil when `old` expires sooner, so it has to be re-issued. The issuer, the key and the
    # range of `not_after` are checked as for a re-issue; only "later than the current" and
    # "not later than the issuer's" are waived (a kept certificate is not capped to the issuer's
    # notAfter). It is not re-signed, so it is also checked to verify under the issuer's key.
    def keep_if_sufficient(old, issuer_cert:, issuer_key:, not_after:, now: Time.now)
      not_after = Time.at(not_after.to_i).utc
      return unless old.not_after >= not_after

      check_issuer_given!(old, issuer_cert)
      signer = issuer_cert || old
      check_key!(signer, issuer_key)
      check_in_range!(not_after, now)
      check_signed_by!(old, signer)
      old
    end

    def check_signed_by!(old, signer)
      return if signed_by?(old, signer)

      raise Error, "#{old.subject} is not signed by the issuer #{signer.subject}; refusing to keep it"
    end

    # OpenSSL raises, rather than answering false, for a signature made with another key type.
    def signed_by?(old, signer)
      old.verify(signer.public_key)
    rescue OpenSSL::OpenSSLError
      false
    end

    # The extension that replaces `extension` in the new certificate: the same bytes, except
    # for the AKI, which is rebuilt from the issuer `signer`.
    def reissued_extension(extension, signer)
      return copy(extension) unless extension.oid == AKI

      regenerated_aki(extension, signer)
    end

    # An extension identical to `extension`: same OID, criticality and DER value.
    def copy(extension)
      OpenSSL::X509::Extension.new(extension.to_der)
    end

    # The AKI of the re-issued certificate: the issuer's key id, and the issuer certificate's
    # own issuer DN and its serial only when `old_aki` carried them. `signer` is the issuer's
    # certificate, or the old certificate for a self-signed root: the serial is kept, so the
    # old certificate's serial is the new one's.
    def regenerated_aki(old_aki, signer)
      key_id = key_id_of(signer)
      der = if names_authority?(old_aki)
              aki_der(key_id, signer.issuer, signer.serial)
            else
              aki_der(key_id, nil, nil)
            end
      value = OpenSSL::ASN1::OctetString.new(der)
      oid = OpenSSL::ASN1::ObjectId.new(AKI)
      parts = [oid]
      parts << OpenSSL::ASN1::Boolean.new(true) if old_aki.critical?
      parts << value
      OpenSSL::X509::Extension.new(OpenSSL::ASN1::Sequence.new(parts).to_der)
    end

    # DER of an AuthorityKeyIdentifier: [0] key id, and when `issuer_name` and `serial` are
    # given, [1] authorityCertIssuer (one directoryName) and [2] authorityCertSerialNumber.
    # `serial` is an OpenSSL::BN or Integer.
    def aki_der(key_id, issuer_name, serial)
      parts = [OpenSSL::ASN1::ASN1Data.new(key_id, 0, :CONTEXT_SPECIFIC)]
      if issuer_name && serial
        directory = OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1.decode(issuer_name.to_der)], 4, :CONTEXT_SPECIFIC)
        parts << OpenSSL::ASN1::ASN1Data.new([directory], 1, :CONTEXT_SPECIFIC)
        parts << OpenSSL::ASN1::ASN1Data.new(integer_content(serial), 2, :CONTEXT_SPECIFIC)
      end
      OpenSSL::ASN1::Sequence.new(parts).to_der
    end

    # The content octets of a DER INTEGER for a non-negative serial: big-endian, with a
    # leading zero when the top bit would otherwise make it negative.
    def integer_content(serial)
      bytes = OpenSSL::BN.new(serial.to_s).to_s(2)
      bytes = "\x00".b if bytes.empty?
      bytes = "\x00".b + bytes if bytes.getbyte(0) >= 0x80
      bytes
    end

    # True if the AKI names its authority by issuer DN and/or serial, not just by key id.
    def names_authority?(aki_extension)
      seq = OpenSSL::ASN1.decode(extension_value_der(aki_extension))
      raise Error, 'The certificate\'s authorityKeyIdentifier is not a SEQUENCE' unless seq.is_a?(OpenSSL::ASN1::Sequence)

      seq.value.any? { |el| el.tag_class == :CONTEXT_SPECIFIC && [1, 2].include?(el.tag) }
    end

    # The DER inside an extension's extnValue OCTET STRING.
    def extension_value_der(extension)
      OpenSSL::ASN1.decode(extension.to_der).value.last.value
    end

    # The key identifier an AKI naming `cert` carries: its SKI, else the SHA-1 of its
    # subjectPublicKey, which is what a `subjectKeyIdentifier=hash` SKI would have been.
    def key_id_of(cert)
      ski = cert.extensions.find { |e| e.oid == SKI }
      return ski_key_id(ski, cert) if ski

      spki = OpenSSL::ASN1.decode(cert.public_key.to_der)
      OpenSSL::Digest.new('SHA1').digest(spki.value[1].value)
    end

    # The key identifier inside an SKI extension, which must be an OCTET STRING.
    def ski_key_id(ski, cert)
      id = OpenSSL::ASN1.decode(extension_value_der(ski))
      raise Error, "The subjectKeyIdentifier of #{cert.subject} is not an OCTET STRING" unless id.is_a?(OpenSSL::ASN1::OctetString)

      raise Error, "The subjectKeyIdentifier of #{cert.subject} is empty" if id.value.empty?

      id.value
    end

    def check_issuer_given!(old, issuer_cert)
      if issuer_cert
        return if old.issuer.to_der == issuer_cert.subject.to_der

        raise Error, "#{old.subject} was issued by #{old.issuer}, not by the given issuer certificate #{issuer_cert.subject}"
      end
      return if old.issuer.to_der == old.subject.to_der

      raise Error, "#{old.subject} is not self-issued, so its issuer certificate is needed (--issuer-cert)"
    end

    def check_key!(signer, key)
      return if key_matches?(signer, key)

      raise Error, "The signing key does not match the issuing certificate #{signer.subject}, " \
                   'so nothing was extended'
    end

    def key_matches?(signer, key)
      signer.check_private_key(key)
    rescue OpenSSL::OpenSSLError
      false
    end

    def check_in_range!(not_after, now)
      return if not_after > now && not_after <= now + (MAX_EXTENSION_DAYS * 86_400)

      raise Error, "The new notAfter #{not_after.iso8601} must lie in the future and at most " \
                   "#{MAX_EXTENSION_DAYS} days ahead"
    end

    def check_not_after!(not_after, old, issuer, now)
      check_in_range!(not_after, now)
      unless not_after > old.not_after
        raise Error, "The new notAfter #{not_after.iso8601} is not later than the current #{old.not_after.utc.iso8601}"
      end
      return unless issuer && not_after > issuer.not_after

      raise Error, "The new notAfter #{not_after.iso8601} is later than the issuer's " \
                   "#{issuer.not_after.utc.iso8601}: extend the root first"
    end

    ISO_TIME = %r{\A(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(\.\d+)?(Z|[+-]\d\d:\d\d)\z}.freeze
    UTC_TIME = %r{\A(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z\z}.freeze

    # Reads either an ISO 8601 date-time with a zone (2041-11-19T12:00:00Z) or UTCTime
    # (YYMMDDHHMMSSZ, where a year of 50 or more is 19YY, as in RFC 5280). A time that is not
    # on the calendar (month 13, 30 February) is refused, not rolled over to another day.
    def parse_time(text)
      time = parse_iso_time(text.to_s) || parse_utc_time(text.to_s)
      return time if time

      raise Error, "#{text.inspect} is not a time: use an ISO 8601 date-time with a zone " \
                   '(2041-11-19T12:00:00Z) or YYMMDDHHMMSSZ'
    end

    def parse_iso_time(text)
      match = ISO_TIME.match(text)
      return unless match && calendar_time?(*match.captures[0..5].map(&:to_i))

      Time.iso8601(text).utc
    rescue ArgumentError
      nil
    end

    def parse_utc_time(text)
      match = UTC_TIME.match(text)
      return unless match

      year, *rest = match.captures.map(&:to_i)
      year += 1900 if year >= 50
      year += 2000 if year < 50
      return unless calendar_time?(year, *rest)

      Time.utc(year, *rest)
    end

    def calendar_time?(year, month, day, hour, minute, second)
      Date.valid_date?(year, month, day) && hour < 24 && minute < 60 && second < 60
    end
  end
end
# rubocop:enable Style/ClassAndModuleChildren
