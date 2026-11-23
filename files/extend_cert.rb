# frozen_string_literal: true

require 'optparse'
require 'openssl'
require_relative 'ca_reissue'

# rubocop:disable Style/ClassAndModuleChildren
# (The CaExtend namespace is shared with files/ca_reissue.rb, so it is not written compactly.)
module CaExtend
  # Command-line entry point for CaExtend::Reissue, run by extend.sh with PE's Ruby.
  #
  #   extend_cert.rb --cert OLD.pem --key ISSUER_KEY.pem --not-after TIME --out NEW.pem
  #                  [--issuer-cert ISSUER.pem] [--keep-if-sufficient]
  #
  # With --keep-if-sufficient, a certificate that already expires no earlier than --not-after is
  # written unchanged (and said so on stderr) instead of being refused as not later.
  #
  # Exit status: 0 on success, 1 when the extension is refused or a file cannot be read or
  # written (a single `ERROR:` line on stderr, nothing written), 2 on a usage error.
  class ExtendCertCli
    REQUIRED = [:cert, :key, :not_after, :out].freeze
    FLAGS = { cert: '--cert', key: '--key', not_after: '--not-after', out: '--out' }.freeze

    def self.run(argv, stdout, stderr)
      new(stdout, stderr).run(argv)
    end

    def initialize(stdout, stderr)
      @stdout = stdout
      @stderr = stderr
    end

    def run(argv)
      options = {}
      parser = option_parser(options)
      begin
        extra = parser.parse(argv)
      rescue OptionParser::ParseError, ArgumentError => e
        # ArgumentError: OptionParser raises it, unwrapped, for an argument that is not valid text.
        return usage_error(parser, e.message)
      end
      return usage_error(parser, "unexpected argument(s): #{extra.join(' ')}") unless extra.empty?
      return help(parser) if options[:help]

      missing = REQUIRED.reject { |name| options[name] }
      return usage_error(parser, "missing required option(s): #{missing.map { |m| FLAGS[m] }.join(', ')}") unless missing.empty?

      extend_certificate(options)
    rescue CaExtend::Reissue::Error => e
      fail_with(e.message)
    end

    private

    def option_parser(options)
      OptionParser.new do |o|
        o.banner = 'Usage: extend_cert.rb --cert FILE --key FILE --not-after TIME --out FILE [--issuer-cert FILE] [--keep-if-sufficient]'
        o.on('--cert FILE', 'The CA certificate to re-issue') { |v| options[:cert] = v }
        o.on('--key FILE', "The issuer's private key (the certificate's own for a self-signed root)") { |v| options[:key] = v }
        o.on('--issuer-cert FILE', 'The issuer certificate; omit for a self-signed root') { |v| options[:issuer_cert] = v }
        o.on('--not-after TIME', 'New notAfter: ISO 8601 date-time with zone (2041-11-19T12:00:00Z) or YYMMDDHHMMSSZ') { |v| options[:not_after] = v }
        o.on('--keep-if-sufficient', 'Write the certificate unchanged if it already expires no earlier than --not-after') do
          options[:keep_if_sufficient] = true
        end
        o.on('--out FILE', 'Where to write the new certificate (PEM)') { |v| options[:out] = v }
        o.on('-h', '--help', 'Show this help') { options[:help] = true }
      end
    end

    def extend_certificate(options)
      old = read_certificate(options[:cert])
      issuer = options[:issuer_cert] ? read_certificate(options[:issuer_cert]) : nil
      key = read_key(options[:key])
      not_after = CaExtend::Reissue.parse_time(options[:not_after])
      new_cert = keep(options, old, issuer, key, not_after) || reissue(options, old, issuer, key, not_after)
      write(options[:out], new_cert.to_pem)
      0
    end

    # With --keep-if-sufficient, a certificate that already expires no earlier than the requested
    # notAfter is written unchanged; nil means the flag is off or it has to be re-issued.
    def keep(options, old, issuer, key, not_after)
      return unless options[:keep_if_sufficient]

      kept = CaExtend::Reissue.keep_if_sufficient(old, issuer_cert: issuer, issuer_key: key, not_after: not_after)
      @stderr.puts("#{options[:cert]} already expires at #{old.not_after.utc.iso8601}: kept unchanged") if kept
      kept
    end

    # An OpenSSL failure while building or signing (a malformed extension, a key the digest
    # cannot use) is reported like any other refusal, not left to print a stack trace.
    def reissue(options, old, issuer, key, not_after)
      CaExtend::Reissue.reissue(old, issuer_cert: issuer, issuer_key: key, not_after: not_after)
    rescue OpenSSL::OpenSSLError => e
      issuer = options[:issuer_cert] || 'itself'
      raise CaExtend::Reissue::Error, "Cannot re-issue #{options[:cert]} (issuer #{issuer}): #{e.class}: #{e.message}"
    end

    def read_certificate(path)
      OpenSSL::X509::Certificate.new(read(path))
    rescue OpenSSL::X509::CertificateError => e
      raise CaExtend::Reissue::Error, "#{path} is not a certificate: #{e.message}"
    end

    def read_key(path)
      key = OpenSSL::PKey.read(read(path), '')
      # Not every key class has private? (an Ed25519 key is a bare PKey), so one that does not
      # is left to the key/issuer match and, failing that, to the signing step, which reports
      # an OpenSSL error.
      private_half = !key.respond_to?(:private?) || key.private?
      raise CaExtend::Reissue::Error, "#{path} is not a private key (it holds a public key)" unless private_half

      key
    rescue OpenSSL::PKey::PKeyError => e
      raise CaExtend::Reissue::Error, "#{path} is not a private key (or is encrypted): #{e.message}"
    end

    def read(path)
      File.read(path)
    rescue SystemCallError => e
      raise CaExtend::Reissue::Error, "Cannot read #{path}: #{e.message}"
    end

    # Written beside the target and renamed, so an error never leaves a partial file.
    def write(path, pem)
      tmp = "#{path}.#{Process.pid}.tmp"
      begin
        File.write(tmp, pem)
        File.rename(tmp, path)
      rescue SystemCallError => e
        remove_quietly(tmp)
        raise CaExtend::Reissue::Error, "Cannot write #{path}: #{e.message}"
      end
    end

    def remove_quietly(path)
      File.delete(path)
    rescue SystemCallError
      nil
    end

    def fail_with(message)
      @stderr.puts("ERROR: #{message}")
      1
    end

    def usage_error(parser, message)
      @stderr.puts("ERROR: #{message}")
      @stderr.puts(parser.help)
      2
    end

    def help(parser)
      @stdout.puts(parser.help)
      0
    end
  end
end

# rubocop:enable Style/ClassAndModuleChildren

exit(CaExtend::ExtendCertCli.run(ARGV, $stdout, $stderr)) if $PROGRAM_NAME == __FILE__
