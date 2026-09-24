# frozen_string_literal: true

require "openssl"
require "tmpdir"

# A CA and a server certificate made on the spot for each test run: nothing secret is kept in the repository, and
# nothing expires between runs.
module TestCertificates
  Files = Data.define(:directory, :ca, :certificate_chain, :private_key)

  def self.key
    OpenSSL::PKey::EC.generate("prime256v1")
  end

  def self.certificate(subject:, key:, issuer: nil, issuer_key: nil, ca: false, not_before: Time.now - 60, not_after: Time.now + 3600)
    certificate = OpenSSL::X509::Certificate.new
    certificate.version = 2
    certificate.serial = OpenSSL::BN.rand(64)
    certificate.subject = OpenSSL::X509::Name.parse(subject)
    certificate.issuer = issuer ? issuer.subject : certificate.subject
    certificate.public_key = key
    certificate.not_before = not_before
    certificate.not_after = not_after

    extensions = OpenSSL::X509::ExtensionFactory.new
    extensions.subject_certificate = certificate
    extensions.issuer_certificate = issuer || certificate
    if ca
      certificate.add_extension(extensions.create_extension("basicConstraints", "CA:TRUE", true))
      certificate.add_extension(extensions.create_extension("keyUsage", "keyCertSign, cRLSign", true))
    else
      certificate.add_extension(extensions.create_extension("basicConstraints", "CA:FALSE", true))
      certificate.add_extension(extensions.create_extension("subjectAltName", "DNS:localhost, IP:127.0.0.1, IP:::1"))
      certificate.add_extension(extensions.create_extension("extendedKeyUsage", "serverAuth"))
    end

    certificate.sign(issuer_key || key, OpenSSL::Digest.new("SHA256"))
    certificate
  end

  # Writes a CA, and a server certificate for localhost, 127.0.0.1 and ::1 signed by it, into a new directory.
  # @returns [Files] The paths; `ca` is the CA certificate a client verifies against.
  def self.write(directory = Dir.mktmpdir("dohyo-tls"), **server_options)
    ca_key = key
    ca = certificate(subject: "/CN=dohyo test CA", key: ca_key, ca: true)
    server_key = key
    server = certificate(subject: "/CN=localhost", key: server_key, issuer: ca, issuer_key: ca_key, **server_options)

    files = Files.new(
      directory:,
      ca: File.join(directory, "ca.pem"),
      certificate_chain: File.join(directory, "fullchain.pem"),
      private_key: File.join(directory, "privkey.pem")
    )
    File.write(files.ca, ca.to_pem)
    File.write(files.certificate_chain, server.to_pem + ca.to_pem)
    File.write(files.private_key, server_key.private_to_pem)
    files
  end
end
