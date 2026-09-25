# frozen_string_literal: true

require "test_helper"
require "net/http"
require "console/capture"
require "console/logger"
require "support/certificates"

# /metrics over real HTTP and HTTPS connections.
class TestMetricsServer < Minitest::Test
  include DohyoTestHelper

  TOKENS = %w[a3f1c0ffee0123456789abcdef0123456789abcdef0123456789abcdef012345 b7e2deadbeef0123456789abcdef0123456789abcdef0123456789abcdef0123].freeze

  def setup
    @certificates = TestCertificates.write
    @metrics = Dohyo::Metrics.new
    @metrics.start(transports: %w[udp], version: Dohyo::VERSION, ruby: RUBY_VERSION)
  end

  def teardown
    FileUtils.rm_rf(@certificates.directory)
  end

  def listen(*addresses) = addresses.map { Dohyo::Config::MetricsListen.new(host: it, port: 0) }

  def with_metrics_server(https: false, tokens: nil)
    tls = Dohyo::TLS.load(certificate_chain: @certificates.certificate_chain, private_key: @certificates.private_key) if https
    host = https ? "::" : "127.0.0.1"

    Sync do |task|
      server = Dohyo::MetricsServer.new(listen: listen(host), metrics: @metrics, tls:, tokens: tokens && Dohyo::BearerTokens.new(tokens))
      server.start(task)
      @port = server.bound_addresses.first.ip_port
      @https = https
      yield server
    ensure
      server&.stop
    end
  end

  # Net::HTTP blocks, so it runs in a thread while the reactor serves.
  def get(path = "/metrics", token: nil, method: Net::HTTP::Get)
    Thread.new do
      http = Net::HTTP.new(@https ? "localhost" : "127.0.0.1", @port)
      if @https
        http.use_ssl = true
        http.ca_file = @certificates.ca
        http.verify_mode = OpenSSL::SSL::VERIFY_PEER
      end
      request = method.new(path)
      request["Authorization"] = "Bearer #{token}" if token
      http.request(request)
    end.value
  end

  def test_loopback_serves_plain_http_without_authentication
    with_metrics_server do
      response = get
      assert_equal "200", response.code
      assert_equal "text/plain; version=0.0.4; charset=utf-8", response["content-type"]
      assert_includes response.body, "# TYPE dohyo_queries_total counter"
      assert_includes response.body, %(dohyo_build_info{version="#{Dohyo::VERSION}",ruby="#{RUBY_VERSION}"} 1)
    end
  end

  def test_other_paths_and_methods
    with_metrics_server do
      assert_equal "404", get("/").code
      assert_equal "404", get("/metrics/x").code
      assert_equal "200", get("/metrics?x=1").code
      response = get(method: Net::HTTP::Post)
      assert_equal "405", response.code
      assert_equal "GET", response["allow"]
    end
  end

  def test_https_needs_a_valid_bearer_token
    with_metrics_server(https: true, tokens: TOKENS) do
      response = get
      assert_equal "401", response.code
      assert_equal "Bearer", response["www-authenticate"]

      assert_equal "401", get(token: "wrong").code
      assert_equal "401", get("/", token: "wrong").code, "nothing but 401 without a valid token"

      TOKENS.each { assert_equal "200", get(token: it).code, "both tokens are valid" }
      assert_equal "404", get("/", token: TOKENS.first).code
    end
  end

  def test_tokens_can_be_replaced
    with_metrics_server(https: true, tokens: TOKENS.take(1)) do |server|
      assert_equal "401", get(token: TOKENS.last).code
      server.tokens = Dohyo::BearerTokens.new(TOKENS.drop(1))
      assert_equal "200", get(token: TOKENS.last).code
      assert_equal "401", get(token: TOKENS.first).code
    end
  end

  def test_tokens_never_appear_in_logs
    capture = Console::Capture.new
    logger = Console::Logger.new(capture, level: :debug)
    previous = Console.logger
    Console.logger = logger

    with_metrics_server(https: true, tokens: TOKENS) do
      get(token: TOKENS.first)
      get(token: TOKENS.first.reverse)
      get(token: TOKENS.first[0, 20])
    end

    logged = capture.map(&:inspect).join("\n")
    assert_match(/metrics.auth_failed/, logged)
    TOKENS.each do |token|
      refute_includes logged, token[0, 16]
      refute_includes logged, token.reverse[0, 16]
    end
  ensure
    Console.logger = previous if previous
  end
end
