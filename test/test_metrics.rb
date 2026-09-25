# frozen_string_literal: true

require "test_helper"

class TestMetrics < Minitest::Test
  def setup
    @metrics = Dohyo::Metrics.new
  end

  def test_query_counts_by_transport_qtype_and_rcode
    @metrics.query(transport: "udp", qtype: 1, rcode: "NOERROR", duration: 0.0002)
    @metrics.query(transport: "udp", qtype: 1, rcode: "NOERROR", duration: 0.0002)
    @metrics.query(transport: "doq", qtype: 16, rcode: "NOERROR", duration: 0.0002)

    assert_equal 2, @metrics.value("dohyo_queries_total", transport: "udp", qtype: "A", rcode: "NOERROR")
    assert_equal 1, @metrics.value("dohyo_queries_total", transport: "doq", qtype: "other", rcode: "NOERROR"), "TXT is not in the zone"
  end

  def test_qtype_labels_are_a_fixed_set
    assert_equal %w[A NS SOA AAAA HTTPS ANY other other], [1, 2, 6, 28, 65, 255, 16, nil].map { Dohyo::Metrics.qtype_label(it) }
  end

  def test_truncated_and_dropped
    @metrics.query(transport: "udp", qtype: 1, rcode: "NOERROR", duration: 0.001, truncated: true)
    @metrics.dropped(transport: "tcp", reason: :too_short)
    assert_equal 1, @metrics.value("dohyo_responses_truncated_total")
    assert_equal 1, @metrics.value("dohyo_queries_dropped_total", transport: "tcp", reason: "too_short")
  end

  def test_connections
    @metrics.connection_opened(transport: "dot")
    @metrics.connection_opened(transport: "dot")
    @metrics.connection_closed(transport: "dot", reason: "idle")
    assert_equal 2, @metrics.value("dohyo_connections_opened_total", transport: "dot")
    assert_equal 1, @metrics.value("dohyo_connections_closed_total", transport: "dot", reason: "idle")
    assert_equal 1, @metrics.value("dohyo_connections_active", transport: "dot")
  end

  def test_start_zeroes_every_rcode_of_each_transport
    @metrics.start(transports: %w[udp udp dot], version: "0.1.0", ruby: "4.0.7")
    Dohyo::Metrics::RCODES.each do |rcode|
      assert_equal 0, @metrics.value("dohyo_queries_total", transport: "udp", qtype: "A", rcode:)
      assert_equal 0, @metrics.value("dohyo_queries_total", transport: "dot", qtype: "A", rcode:)
    end
    assert_nil @metrics.value("dohyo_queries_total", transport: "tcp", qtype: "A", rcode: "NOERROR")
    assert_equal 0, @metrics.value("dohyo_connections_active", transport: "dot")
    assert_equal 1, @metrics.value("dohyo_build_info", version: "0.1.0", ruby: "4.0.7")
  end

  def test_zone
    at = Time.at(1_790_000_000.5)
    @metrics.zone_loaded(serial: 2026092301, at:)
    @metrics.zone_reload(result: "failure")
    assert_equal 2026092301, @metrics.value("dohyo_zone_serial")
    assert_equal 1_790_000_000.5, @metrics.value("dohyo_zone_loaded_timestamp_seconds")
    assert_equal 1, @metrics.value("dohyo_zone_reloads_total", result: "failure")
  end

  def test_render
    @metrics.start(transports: %w[udp], version: "0.1.0", ruby: "4.0.7")
    @metrics.query(transport: "udp", qtype: 28, rcode: "NXDOMAIN", duration: 0.0003)
    @metrics.query(transport: "udp", qtype: 28, rcode: "NXDOMAIN", duration: 0.2)
    text = @metrics.render

    assert text.end_with?("\n")
    assert_includes text, "# HELP dohyo_queries_total Queries answered, by transport, question type and RCODE.\n# TYPE dohyo_queries_total counter\n"
    assert_includes text, %(dohyo_queries_total{transport="udp",qtype="AAAA",rcode="NXDOMAIN"} 2\n)
    assert_includes text, %(dohyo_queries_total{transport="udp",qtype="A",rcode="SERVFAIL"} 0\n)
    assert_includes text, "# TYPE dohyo_query_duration_seconds histogram\n"
    assert_includes text, %(dohyo_query_duration_seconds_bucket{transport="udp",le="0.00025"} 0\n)
    assert_includes text, %(dohyo_query_duration_seconds_bucket{transport="udp",le="0.0005"} 1\n)
    assert_includes text, %(dohyo_query_duration_seconds_bucket{transport="udp",le="0.1"} 1\n)
    assert_includes text, %(dohyo_query_duration_seconds_bucket{transport="udp",le="+Inf"} 2\n)
    assert_includes text, %(dohyo_query_duration_seconds_count{transport="udp"} 2\n)
    assert_match(/^dohyo_query_duration_seconds_sum\{transport="udp"\} 0\.2003/, text)
    assert_includes text, %(dohyo_build_info{version="0.1.0",ruby="4.0.7"} 1\n)
    refute_includes text, "dohyo_zone_serial", "series without values are left out"
  end

  def test_render_escapes_label_values
    @metrics.dropped(transport: %(a"b\\c\nd), reason: "x")
    assert_includes @metrics.render, %(transport="a\\"b\\\\c\\nd")
  end
end
