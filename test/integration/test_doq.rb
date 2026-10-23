# frozen_string_literal: true

require "test_helper"
require "open3"
require "support/certificates"

begin
  require "support/doq_client"
rescue LoadError
  # protocol-quic is not installed; every test below skips.
end

# The DoQ rows of the test case table (28 and Q1-Q8), against Dohyo::Server over real QUIC connections.
class TestDoQ < Minitest::Test
  include DohyoTestHelper

  def setup
    skip "protocol-quic is not installed" unless defined?(DoQTestClient)

    @certificates = TestCertificates.write
    @clients = []
  end

  def teardown
    @clients&.each(&:stop)
    FileUtils.rm_rf(@certificates.directory) if @certificates
  end

  def with_server(max_connections: 16, idle_timeout: 10)
    tls = Dohyo::TLS.load(certificate_chain: @certificates.certificate_chain, private_key: @certificates.private_key)

    Sync do |task|
      @task = task
      server = Dohyo::Server.new(zone: fixture_zone, listen: [Dohyo::Server::Listen.parse("quic://127.0.0.1:0")],
        udp_payload_size: 1232, max_connections:, idle_timeout:, tls:)
      server.start(task)
      @address = server.bound_addresses.first.last
      @server = server
      yield server
    ensure
      @clients.each(&:stop)
      server&.stop
    end
  end

  def connect(**options)
    client = DoQTestClient.connect(@address, **options)
    @clients << client
    assert client.start(@task), "handshake"
    client
  end

  def eventually(expected, seconds: 1)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + seconds
    loop do
      actual = yield
      return actual if actual == expected || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

      sleep 0.02
    end
  end

  def decode(data)
    length = data.unpack1("n")
    assert_equal data.bytesize - 2, length, "one length-prefixed message"
    Resolv::DNS::Message.decode(data.byteslice(2, length))
  end

  def test_q1_and_case_28_one_query_one_response
    with_server do
      response = decode(connect.query(query_bytes("big.blog.example.com.", IN::A, id: 0)).wait)
      assert_equal 0, response.id
      assert_equal 0, response.tc
      assert_equal 40, response.answer.size
    end
  end

  def test_queries_are_counted_but_protocol_errors_are_not
    with_server do |server|
      client = connect
      assert_equal 0, decode(client.query(query_bytes("blog.example.com.", IN::AAAA, id: 0)).wait).rcode
      client.query(query_bytes("blog.example.com.", IN::A, id: 7))
      client.wait_for_close

      assert_equal 1, server.metrics.value("dohyo_queries_total", transport: "doq", qtype: "AAAA", rcode: "NOERROR")
      assert_equal 0, server.metrics.value("dohyo_queries_total", transport: "doq", qtype: "A", rcode: "NOERROR"), "zeroed at start, never counted"
      assert_nil server.metrics.value("dohyo_queries_dropped_total", transport: "doq", reason: "too_short")
    end
  end

  def test_q2_several_streams_on_one_connection
    with_server do
      client = connect
      streams = [["blog.example.com.", IN::A], ["blog.example.com.", IN::AAAA], ["nope.blog.example.com.", IN::A]].map do |name, type|
        client.query(query_bytes(name, type, id: 0))
      end
      rcodes = streams.map { decode(it.wait).rcode }
      assert_equal [0, 0, Resolv::DNS::RCode::NXDomain], rcodes
    end
  end

  def test_many_streams_beyond_the_initial_limit
    with_server do
      client = connect
      # More than doq.max_streams_per_connection (16) in total: the limit must be raised as streams close.
      20.times do
        assert_equal 0, decode(client.query(query_bytes("blog.example.com.", IN::A, id: 0)).wait).rcode
      end
    end
  end

  def test_q3_nonzero_message_id_is_a_protocol_error
    with_server do
      client = connect
      client.query(query_bytes("blog.example.com.", IN::A, id: 1))
      assert_equal [:application, Dohyo::DoQ::PROTOCOL_ERROR], client.wait_for_close
    end
  end

  def test_q4_fin_before_the_whole_message_is_a_protocol_error
    with_server do
      client = connect
      message = query_bytes("blog.example.com.", IN::A, id: 0)
      client.send_stream([message.bytesize].pack("n") + message.byteslice(0, 5))
      assert_equal [:application, Dohyo::DoQ::PROTOCOL_ERROR], client.wait_for_close
    end
  end

  def test_q5_two_queries_on_one_stream_is_a_protocol_error
    with_server do
      client = connect
      message = query_bytes("blog.example.com.", IN::A, id: 0)
      framed = [message.bytesize].pack("n") + message
      client.send_stream(framed * 2)
      assert_equal [:application, Dohyo::DoQ::PROTOCOL_ERROR], client.wait_for_close
    end
  end

  def test_q6_edns_tcp_keepalive_is_a_protocol_error
    with_server do
      client = connect
      client.query(query_bytes("blog.example.com.", IN::A, id: 0, edns: 1232, edns_data: [11, 0].pack("nn")))
      assert_equal [:application, Dohyo::DoQ::PROTOCOL_ERROR], client.wait_for_close
    end
  end

  def test_q7_another_alpn_fails_the_handshake
    with_server do
      client = DoQTestClient.connect(@address, alpn: "dot")
      @clients << client
      refute client.start(@task), "no handshake without doq"
    end
  end

  def test_q8_idle_connections_are_closed
    with_server(idle_timeout: 1) do |server|
      connect
      # The server counts the connection when it sees the handshake complete, a little after the client does:
      assert_equal 1, eventually(1) { server.connection_count }
      assert_equal 0, eventually(0, seconds: 3) { server.connection_count }
      assert_equal 1, server.metrics.value("dohyo_connections_opened_total", transport: "doq")
      assert_equal 0, server.metrics.value("dohyo_connections_active", transport: "doq")
    end
  end

  def test_connections_beyond_the_limit_get_excessive_load
    with_server(max_connections: 1) do
      connect
      second = connect
      assert_equal [:application, Dohyo::DoQ::EXCESSIVE_LOAD], second.wait_for_close
      assert_equal 1, eventually(1) { @server.metrics.value("dohyo_connections_closed_total", transport: "doq", reason: "limit") }
      assert_equal 1, @server.metrics.value("dohyo_connections_active", transport: "doq")
    end
  end

  # Stands in for DoQ::Connection where the Listener calls it, so that connections can be held in the handshake.
  FakeConnection = Struct.new(:listener, :events, :opened_at, :queries, :close_reason, :counted, :handshaking, :closed_with) do
    def event(*event) = events&.push(event)

    def handshake_completed
      listener.handshake_over(self)
      event(:handshake)
    end

    def run = nil

    def send_packets = nil

    def disconnected? = !closed_with.nil?

    # As DoQ::Connection#disconnected does once the connection is closed.
    def close(code)
      self.closed_with = code
      events.close
      listener.connection_gone(self)
    end
  end

  FakeStream = Struct.new(:buffer, :written) do
    def write(data) = (self.written = data)

    def finish = nil
  end

  def with_listener(max_connections:)
    require "dohyo/doq"
    tls = Dohyo::TLS.load(certificate_chain: @certificates.certificate_chain, private_key: @certificates.private_key)
    engine = Dohyo::Engine.new(zone_provider: -> { fixture_zone }, udp_payload_size: 1232)
    @metrics = Dohyo::Metrics.new

    Sync do |task|
      listener = Dohyo::DoQ::Listener.new(host: "127.0.0.1", port: 0, engine:, limiter: Dohyo::ConnectionLimiter.new(max_connections),
        idle_timeout: 10, max_streams: 16, certificate: tls, metrics: @metrics)
      runner = task.async { listener.run }
      yield listener
    ensure
      runner&.stop
      listener&.close
    end
  end

  def test_connections_beyond_the_handshake_limit_are_closed
    with_listener(max_connections: 2) do |listener|
      first, second, third = Array.new(3) { FakeConnection.new }
      [first, second, third].each { listener.connection_created(it) }
      assert_equal Dohyo::DoQ::EXCESSIVE_LOAD, eventually(Dohyo::DoQ::EXCESSIVE_LOAD) { third.closed_with }
      assert_equal "handshake_limit", third.close_reason
      assert_nil first.closed_with
      assert_nil second.closed_with
      assert_equal 1, @metrics.value("dohyo_connections_closed_total", transport: "doq", reason: "handshake_limit")

      # A completed handshake frees a place:
      first.handshake_completed
      assert eventually(true) { first.counted }
      fourth = FakeConnection.new
      listener.connection_created(fourth)

      # So does a connection that goes away:
      second.close(Dohyo::DoQ::NO_ERROR)
      fifth = FakeConnection.new
      listener.connection_created(fifth)

      sixth = FakeConnection.new
      listener.connection_created(sixth)
      assert_equal Dohyo::DoQ::EXCESSIVE_LOAD, eventually(Dohyo::DoQ::EXCESSIVE_LOAD) { sixth.closed_with }
      assert_nil fourth.closed_with
      assert_nil fifth.closed_with
    end
  end

  def test_queries_left_on_a_closed_connection_are_not_answered
    with_listener(max_connections: 1) do |listener|
      listener.connection_created(FakeConnection.new)
      refused = FakeConnection.new
      listener.connection_created(refused)
      # Queued before serve gets to the refusal:
      query = query_bytes("blog.example.com.", IN::A, id: 0)
      stream = FakeStream.new([query.bytesize].pack("n") + query)
      refused.event(:query, stream)

      assert_equal Dohyo::DoQ::EXCESSIVE_LOAD, eventually(Dohyo::DoQ::EXCESSIVE_LOAD) { refused.closed_with }
      sleep 0.05
      assert_nil stream.written, "no answer"
      assert_nil @metrics.value("dohyo_queries_total", transport: "doq", qtype: "A", rcode: "NOERROR")
    end
  end

  def test_shutdown_closes_connections_with_no_error
    with_server do |server|
      client = connect
      assert_equal 0, decode(client.query(query_bytes("blog.example.com.", IN::A, id: 0)).wait).rcode
      server.shutdown(grace: 1)
      assert_equal [:application, Dohyo::DoQ::NO_ERROR], client.wait_for_close
    end
  end

  def test_kdig
    skip "kdig is not installed" unless system("which kdig", out: File::NULL, err: File::NULL)

    with_server do
      output = Thread.new do
        Open3.capture2e("kdig", "@#{@address.ip_address}", "-p", @address.ip_port.to_s, "+quic", "+retry=0", "+timeout=3",
          "+keepopen", "big.blog.example.com", "A", "blog.example.com", "HTTPS").first
      end.value
      assert_match(/QUIC session/, output)
      assert_equal 40, output.scan(/\bIN\s+A\s+192\.0\.2\./).size
      assert_match(/alpn="?h3,h2"?/, output)
    end
  end
end
