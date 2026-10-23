# frozen_string_literal: true

require "openssl"

require_relative "errors"

module Dohyo
  # The server certificate shared by DoT, DoQ and /metrics, and the TLS context built from it.
  module TLS
    # `chain_path` and `key_path` are kept for protocol-quic, which reads the files itself.
    Certificate = Data.define(:certificate, :chain, :key, :chain_path, :key_path)

    # Reads and checks the certificate chain and its private key. Unreadable files, a key readable by group or
    # others, a key that does not match the certificate, and a certificate outside its validity period all refuse
    # startup.
    #
    # @parameter now [Time] For tests.
    # @returns [Certificate]
    def self.load(certificate_chain:, private_key:, now: Time.now)
      certificates = begin
        OpenSSL::X509::Certificate.load(File.read(certificate_chain))
      rescue SystemCallError, OpenSSL::X509::CertificateError => error
        raise ConfigError, "cannot read the certificate chain #{certificate_chain}: #{error.message}"
      end
      raise ConfigError, "no certificate in #{certificate_chain}" if certificates.empty?

      key = begin
        # The same rule as for the metrics token file: File.stat follows a symbolic link to the key itself.
        mode = File.stat(private_key).mode
        unless (mode & 0o077).zero?
          raise ConfigError, "the private key #{private_key} must not be readable by group or others (it is #{format("%04o", mode & 0o7777)}; use 0600 or 0400)"
        end

        OpenSSL::PKey.read(File.read(private_key))
      rescue SystemCallError, OpenSSL::PKey::PKeyError => error
        raise ConfigError, "cannot read the private key #{private_key}: #{error.message}"
      end

      certificate, *chain = certificates
      raise ConfigError, "the private key #{private_key} does not match the certificate in #{certificate_chain}" unless certificate.check_private_key(key)

      if now < certificate.not_before || now > certificate.not_after
        raise ConfigError, "the certificate in #{certificate_chain} is valid only from #{certificate.not_before} to #{certificate.not_after}"
      end

      Certificate.new(certificate:, chain:, key:, chain_path: certificate_chain, key_path: private_key)
    end

    # A server context: TLS 1.3 only, no client certificates, no compression, the default cipher suites.
    #
    # TLS 1.3 alone is enough for the resolvers that probe DoT (RFC 9539) and for Prometheus; older clients are
    # knowingly left out. Session tickets stay enabled with OpenSSL's per-process keys, so a restart invalidates them.
    #
    # @parameter alpn [Array<String>, nil] Protocols to offer; DoT sets none.
    def self.server_context(certificate, alpn: nil)
      context = OpenSSL::SSL::SSLContext.new
      context.min_version = OpenSSL::SSL::TLS1_3_VERSION
      context.verify_mode = OpenSSL::SSL::VERIFY_NONE
      context.options |= OpenSSL::SSL::OP_NO_COMPRESSION
      context.add_certificate(certificate.certificate, certificate.key, certificate.chain)

      if alpn
        context.alpn_protocols = alpn
        # Raising ends the handshake with a no_application_protocol alert (RFC 7301 §3.2). Returning nil instead
        # makes openssl raise TypeError, which the handshake's rescue does not expect.
        context.alpn_select_cb = ->(offered) { (alpn & offered).first || raise(OpenSSL::SSL::SSLError, "no application protocol in common") }
      end

      context
    end
  end
end
