# frozen_string_literal: true

require "test_helper"
require "support/certificates"

class TestTLS < Minitest::Test
  def setup
    @files = TestCertificates.write
  end

  def teardown
    FileUtils.rm_rf(@files.directory)
  end

  def load(**options)
    Dohyo::TLS.load(certificate_chain: @files.certificate_chain, private_key: @files.private_key, **options)
  end

  def test_loads_the_certificate_and_its_chain
    certificate = load
    assert_equal "/CN=localhost", certificate.certificate.subject.to_s
    assert_equal ["/CN=dohyo test CA"], certificate.chain.map { it.subject.to_s }
  end

  def test_unreadable_files
    error = assert_raises(Dohyo::ConfigError) { Dohyo::TLS.load(certificate_chain: "/nonexistent.pem", private_key: @files.private_key) }
    assert_match(/cannot read the certificate chain/, error.message)

    error = assert_raises(Dohyo::ConfigError) { Dohyo::TLS.load(certificate_chain: @files.certificate_chain, private_key: "/nonexistent.pem") }
    assert_match(/cannot read the private key/, error.message)
  end

  def test_not_a_certificate
    File.write(@files.certificate_chain, "garbage")
    error = assert_raises(Dohyo::ConfigError) { load }
    assert_match(/certificate/, error.message)
  end

  def test_key_must_be_readable_by_its_owner_only
    [0o644, 0o640].each do |mode|
      File.chmod(mode, @files.private_key)
      error = assert_raises(Dohyo::ConfigError) { load }
      assert_match(/must not be readable by group or others \(it is #{format("%04o", mode)}; use 0600 or 0400\)/, error.message)
    end

    [0o600, 0o400].each do |mode|
      File.chmod(mode, @files.private_key)
      assert load, format("%04o", mode)
    end
  end

  def test_key_must_match_the_certificate
    File.write(@files.private_key, TestCertificates.key.private_to_pem)
    error = assert_raises(Dohyo::ConfigError) { load }
    assert_match(/does not match/, error.message)
  end

  def test_expired_and_not_yet_valid
    assert_raises(Dohyo::ConfigError) { load(now: Time.now + 7200) }
    assert_raises(Dohyo::ConfigError) { load(now: Time.now - 7200) }
  end

  def test_server_context
    context = Dohyo::TLS.server_context(load)
    assert_equal OpenSSL::SSL::VERIFY_NONE, context.verify_mode
    assert_equal OpenSSL::SSL::OP_NO_COMPRESSION, context.options & OpenSSL::SSL::OP_NO_COMPRESSION
    assert_nil context.alpn_protocols
  end

  def test_server_context_refuses_tls_1_2
    context = Dohyo::TLS.server_context(load)
    server = OpenSSL::SSL::SSLServer.new(TCPServer.new("127.0.0.1", 0), context)
    port = server.to_io.local_address.ip_port

    accepting = Thread.new do
      server.accept
    rescue OpenSSL::SSL::SSLError
      nil
    end

    client_context = OpenSSL::SSL::SSLContext.new
    client_context.max_version = OpenSSL::SSL::TLS1_2_VERSION
    client = OpenSSL::SSL::SSLSocket.new(TCPSocket.new("127.0.0.1", port), client_context)
    assert_raises(OpenSSL::SSL::SSLError) { client.connect }
  ensure
    accepting&.join(1)
    server&.close
  end

  def test_server_context_with_alpn
    context = Dohyo::TLS.server_context(load, alpn: ["http/1.1"])
    assert_equal ["http/1.1"], context.alpn_protocols
    assert_equal "http/1.1", context.alpn_select_cb.call(["h2", "http/1.1"])
  end

  def test_server_context_refuses_a_client_without_a_common_alpn_protocol
    context = Dohyo::TLS.server_context(load, alpn: ["http/1.1"])
    assert_raises(OpenSSL::SSL::SSLError) { context.alpn_select_cb.call(["h2"]) }
  end
end
