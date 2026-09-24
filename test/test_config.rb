# frozen_string_literal: true

require "test_helper"
require "tmpdir"

class TestConfig < Minitest::Test
  MINIMAL = <<~YAML
    zone:
      origin: blog.example.com.
      file: /etc/dohyo/zones/blog.example.com.zone
    listen:
      - udp://127.0.0.1:53
  YAML

  FULL = <<~YAML
    zone:
      origin: Blog.Example.COM.
      file: /etc/dohyo/zones/blog.example.com.zone
    listen:
      - udp://0.0.0.0:53
      - udp://[::]:53
      - tcp://0.0.0.0:53
      - tls://[::]:853
      - quic://[::]:853
    tls:
      certificate_chain: /etc/dohyo/tls/fullchain.pem
      private_key: /etc/dohyo/tls/privkey.pem
    edns:
      udp_payload_size: 4096
    connection:
      idle_timeout: 30
      max_connections: 64
    doq:
      max_streams_per_connection: 8
    metrics:
      listen:
        - "0.0.0.0:9153"
        - "[::]:9153"
      bearer_token_file: /etc/dohyo/secrets/metrics-tokens
  YAML

  def parse(text)
    Dohyo::Config.parse(text)
  end

  def assert_config_error(pattern, text)
    error = assert_raises(Dohyo::ConfigError) { parse(text) }
    assert_match pattern, error.message
  end

  def test_minimal_uses_the_defaults
    config = parse(MINIMAL)
    assert_equal "blog.example.com.", config.zone_origin
    assert_equal "/etc/dohyo/zones/blog.example.com.zone", config.zone_file
    assert_equal ["udp://127.0.0.1:53"], config.listen.map(&:to_s)
    assert_nil config.tls
    assert_equal 1232, config.udp_payload_size
    assert_equal 10, config.idle_timeout
    assert_equal 256, config.max_connections
    assert_equal 16, config.doq_max_streams
    assert_nil config.metrics
    refute config.tls_required?
  end

  def test_full
    config = parse(FULL)
    assert_equal "blog.example.com.", config.zone_origin, "the origin is lowercased"
    assert_equal %w[udp udp tcp tls quic], config.listen.map(&:scheme)
    assert_equal "::", config.listen[1].host
    assert_equal "/etc/dohyo/tls/fullchain.pem", config.tls.certificate_chain
    assert_equal [4096, 30, 64, 8], [config.udp_payload_size, config.idle_timeout, config.max_connections, config.doq_max_streams]
    assert_equal ["0.0.0.0:9153", "[::]:9153"], config.metrics.listen.map(&:to_s)
    assert_equal "/etc/dohyo/secrets/metrics-tokens", config.metrics.bearer_token_file
    assert config.metrics.exposed?
    assert config.tls_required?
  end

  def test_metrics_listen_defaults
    config = parse(FULL.sub(/  listen:\n    - "0.0.0.0:9153"\n    - "\[::\]:9153"\n/, ""))
    assert_equal ["0.0.0.0:9153", "[::]:9153"], config.metrics.listen.map(&:to_s)
  end

  def test_metrics_on_loopback_needs_neither_tls_nor_token
    config = parse(MINIMAL + <<~YAML)
      metrics:
        listen:
          - "127.0.0.1:9153"
          - "[::1]:9153"
    YAML
    refute config.metrics.exposed?
    assert_nil config.metrics.bearer_token_file
  end

  def test_exposed_metrics_need_a_token
    assert_config_error(/metrics.bearer_token_file is required/, FULL.sub(/  bearer_token_file: .*\n/, ""))
  end

  def test_exposed_metrics_need_tls
    text = FULL.sub(/tls:\n  certificate_chain: .*\n  private_key: .*\n/, "").gsub(/  - (tls|quic):.*\n/, "")
    assert_config_error(/tls.certificate_chain and tls.private_key are required when metrics/, text)
  end

  def test_tls_and_quic_listeners_need_tls
    assert_config_error(/required for tls:\/\/ and quic:\/\//, MINIMAL + "  - tls://[::]:853\n")
  end

  def test_unknown_keys_are_rejected_with_their_location
    assert_config_error(/unknown key connection.idle_timout/, MINIMAL + "connection:\n  idle_timout: 10\n")
    assert_config_error(/unknown key zonee/, MINIMAL + "zonee: x\n")
  end

  def test_required_keys
    assert_config_error(/zone.origin is required/, MINIMAL.sub(/  origin: .*\n/, ""))
    assert_config_error(/zone.file is required/, MINIMAL.sub(/  file: .*\n/, ""))
    assert_config_error(/listen is required/, MINIMAL.sub(/listen:\n.*\n/, ""))
  end

  def test_listen_must_not_be_empty
    assert_config_error(/listen must be a list/, MINIMAL.sub(/listen:\n.*\n/, "listen: []\n"))
  end

  def test_duplicate_listeners
    assert_config_error(/more than once/, MINIMAL + "  - udp://127.0.0.1:53\n")
    assert_config_error(/metrics.listen has 127.0.0.1:9153 more than once/, MINIMAL + "metrics:\n  listen: ['127.0.0.1:9153', '127.0.0.1:9153']\n")
  end

  def test_tls_and_quic_on_the_same_address_do_not_conflict
    config = parse(FULL)
    assert_equal 2, config.listen.count { it.host == "::" && it.port == 853 }
  end

  def test_invalid_listen_addresses
    assert_config_error(/unsupported scheme "http"/, MINIMAL.sub("udp://127.0.0.1:53", "http://127.0.0.1:53"))
    assert_config_error(/expected scheme:\/\/host:port/, MINIMAL.sub("udp://127.0.0.1:53", "udp://::1:53"))
    assert_config_error(/expected scheme:\/\/host:port/, MINIMAL.sub("udp://127.0.0.1:53", "udp://127.0.0.1"))
    assert_config_error(/port out of range/, MINIMAL.sub("udp://127.0.0.1:53", "udp://127.0.0.1:65536"))
    assert_config_error(/expected host:port/, MINIMAL + "metrics:\n  listen: ['https://127.0.0.1:9153']\n")
  end

  def test_value_ranges
    assert_config_error(/edns.udp_payload_size must be within 512..4096/, MINIMAL + "edns:\n  udp_payload_size: 511\n")
    assert_config_error(/edns.udp_payload_size must be within 512..4096/, MINIMAL + "edns:\n  udp_payload_size: 4097\n")
    assert_config_error(/connection.idle_timeout must be within 1../, MINIMAL + "connection:\n  idle_timeout: 0\n")
    assert_config_error(/connection.idle_timeout must be an integer/, MINIMAL + "connection:\n  idle_timeout: 1.5\n")
    assert_config_error(/connection.max_connections must be an integer/, MINIMAL + "connection:\n  max_connections: '10'\n")
    assert_config_error(/doq.max_streams_per_connection must be within 1../, MINIMAL + "doq:\n  max_streams_per_connection: 0\n")
  end

  def test_origin_must_be_absolute
    assert_config_error(/absolute name with a trailing dot/, MINIMAL.sub("blog.example.com.", "blog.example.com"))
  end

  def test_sections_must_be_mappings
    assert_config_error(/zone must be a mapping/, "zone: blog.example.com.\nlisten: ['udp://127.0.0.1:53']\n")
  end

  def test_yaml_is_loaded_safely
    assert_config_error(/cannot parse/, MINIMAL + "edns: &a\n  udp_payload_size: 1232\ndoq: *a\n")
    assert_config_error(/cannot parse/, MINIMAL.sub("file: /etc/dohyo/zones/blog.example.com.zone", "file: :symbol"))
    assert_config_error(/must be a mapping/, "- a\n- b\n")
  end

  def test_load_reports_an_unreadable_file
    error = assert_raises(Dohyo::ConfigError) { Dohyo::Config.load("/nonexistent/dohyo.yml") }
    assert_match(/cannot read/, error.message)
  end

  def test_load_reads_a_file
    Dir.mktmpdir do |dir|
      path = File.join(dir, "dohyo.yml")
      File.write(path, MINIMAL)
      assert_equal "blog.example.com.", Dohyo::Config.load(path).zone_origin
    end
  end
end
