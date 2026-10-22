# frozen_string_literal: true

require "test_helper"
require "async"
require "async/dns"
require "open3"
require "console/capture"
require "console/logger"
require "support/certificates"

# Starts Dohyo::Server on loopback ports chosen by the OS and queries it over real sockets.
class TestServerIntegration < Minitest::Test
  include DohyoTestHelper

  LISTEN = %w[udp://127.0.0.1:0 tcp://127.0.0.1:0 udp://[::1]:0 tcp://[::1]:0 tls://127.0.0.1:0].freeze

  def setup
    @certificates = TestCertificates.write
  end

  def teardown
    FileUtils.rm_rf(@certificates.directory)
  end

  def with_server(listen: LISTEN, max_connections: 256, idle_timeout: 10)
    tls = Dohyo::TLS.load(certificate_chain: @certificates.certificate_chain, private_key: @certificates.private_key)

    Sync do |task|
      server = Dohyo::Server.new(zone: fixture_zone, listen: listen.map { Dohyo::Server::Listen.parse(it) }, udp_payload_size: 1232, max_connections:, idle_timeout:, tls:)
      server.start(task)
      yield server
    ensure
      server&.stop
    end
  end

  def address_of(server, transport, family = :ipv4?)
    server.bound_addresses.find { |t, address| t == transport && address.public_send(family) }.last
  end

  def resolver_for(address, transport)
    endpoint = (transport == "udp") ? IO::Endpoint.udp(address.ip_address, address.ip_port) : IO::Endpoint.tcp(address.ip_address, address.ip_port)
    Async::DNS::Resolver.new(endpoint)
  end

  def udp_exchange(address, bytes)
    socket = Socket.new(address.afamily, Socket::SOCK_DGRAM)
    socket.send(bytes, 0, address.to_sockaddr)
    socket.recv(65535)
  ensure
    socket&.close
  end

  def tcp_exchange(address, *messages)
    socket = Socket.tcp(address.ip_address, address.ip_port)
    stream_exchange(socket, messages)
  ensure
    socket&.close
  end

  # Connects with certificate verification against the test CA, as a DoT client with a known name would.
  def dot_exchange(address, *messages)
    socket = dot_connect(address)
    stream_exchange(socket, messages)
  ensure
    socket&.close
  end

  def dot_connect(address)
    context = OpenSSL::SSL::SSLContext.new
    context.set_params(verify_mode: OpenSSL::SSL::VERIFY_PEER, ca_file: @certificates.ca)
    socket = OpenSSL::SSL::SSLSocket.new(Socket.tcp(address.ip_address, address.ip_port), context)
    socket.sync_close = true
    socket.hostname = "localhost"
    socket.connect
    socket.post_connection_check("localhost")
    socket
  end

  def stream_exchange(socket, messages)
    messages.map do |bytes|
      socket.write([bytes.bytesize].pack("n") + bytes)
      socket.flush
      length = socket.read(2).unpack1("n")
      socket.read(length)
    end
  end

  def test_udp_and_tcp_over_ipv4_and_ipv6
    with_server do |server|
      %w[udp tcp].product(%i[ipv4? ipv6?]).each do |transport, family|
        response = resolver_for(address_of(server, transport, family), transport).query("blog.example.com", IN::A)
        assert_equal ["192.0.2.1"], response.answer.map { it[2].address.to_s }, "#{transport} #{family}"
        assert_equal 1, response.aa
      end
    end
  end

  def test_nxdomain_over_udp
    with_server do |server|
      bytes = udp_exchange(address_of(server, "udp"), query_bytes("nope.blog.example.com.", IN::A))
      response = Resolv::DNS::Message.decode(bytes)
      assert_equal Resolv::DNS::RCode::NXDomain, response.rcode
      assert_equal 4242, response.id
    end
  end

  def test_big_answer_is_truncated_over_udp_and_complete_over_tcp
    with_server do |server|
      udp = udp_exchange(address_of(server, "udp"), query_bytes("big.blog.example.com.", IN::A))
      assert_equal 1, header_of(udp)[:tc]
      assert_equal 1, header_of(udp)[:qdcount]

      tcp = tcp_exchange(address_of(server, "tcp"), query_bytes("big.blog.example.com.", IN::A)).first
      assert_equal 40, Resolv::DNS::Message.decode(tcp).answer.size
    end
  end

  def test_case_28_big_answer_over_dot_is_not_truncated
    with_server do |server|
      response = dot_exchange(address_of(server, "dot"), query_bytes("big.blog.example.com.", IN::A)).first
      message = Resolv::DNS::Message.decode(response)
      assert_equal 0, message.tc
      assert_equal 40, message.answer.size
    end
  end

  def test_several_queries_on_one_dot_connection
    with_server do |server|
      responses = dot_exchange(address_of(server, "dot"),
        query_bytes("blog.example.com.", IN::A, id: 1), query_bytes("nope.blog.example.com.", IN::A, id: 2))
      assert_equal [[1, 0], [2, Resolv::DNS::RCode::NXDomain]], responses.map {
        m = Resolv::DNS::Message.decode(it)
        [m.id, m.rcode]
      }
    end
  end

  def test_dot_offers_tls_1_3_only
    with_server do |server|
      address = address_of(server, "dot")
      context = OpenSSL::SSL::SSLContext.new
      context.max_version = OpenSSL::SSL::TLS1_2_VERSION
      socket = OpenSSL::SSL::SSLSocket.new(Socket.tcp(address.ip_address, address.ip_port), context)
      assert_raises(OpenSSL::SSL::SSLError) { socket.connect }
    ensure
      socket&.close
    end
  end

  def test_connections_beyond_the_limit_are_closed_at_once
    with_server(max_connections: 1) do |server|
      tcp = address_of(server, "tcp")
      first = Socket.tcp(tcp.ip_address, tcp.ip_port)
      assert_equal 1, stream_exchange(first, [query_bytes("blog.example.com.", IN::A)]).size

      # TCP and DoT share the limit:
      second = Socket.tcp(tcp.ip_address, tcp.ip_port)
      assert_nil second.read(1), "closed without an answer"
      assert_raises(OpenSSL::SSL::SSLError, Errno::ECONNRESET, EOFError) { dot_exchange(address_of(server, "dot"), query_bytes("blog.example.com.", IN::A)) }

      first.close
      responses = nil
      20.times do
        responses = tcp_exchange(tcp, query_bytes("blog.example.com.", IN::A))
        break
      rescue NoMethodError, Errno::ECONNRESET
        sleep 0.05 # The first connection's slot is released asynchronously.
      end
      assert_equal 1, responses&.size

      metrics = server.metrics
      assert_equal 1, metrics.value("dohyo_connections_closed_total", transport: "tcp", reason: "limit")
      assert_equal 1, metrics.value("dohyo_connections_closed_total", transport: "dot", reason: "limit")
      assert_operator metrics.value("dohyo_connections_opened_total", transport: "tcp"), :>=, 3
    ensure
      first&.close
      second&.close
    end
  end

  # Runs Server::Wrapper#accept on a loopback listener whose first accept raises `error`, then connects once.
  # @returns [Boolean] Whether the connection reached the block.
  def accept_once_after(error)
    wrapper = Dohyo::Server::Wrapper.new
    failures = [error]
    wrapper.define_singleton_method(:socket_accept) do |server|
      raise failures.shift unless failures.empty?

      super(server)
    end

    listener = Socket.new(:INET, :STREAM)
    listener.bind(Addrinfo.tcp("127.0.0.1", 0))
    listener.listen(8)
    accepted = Thread::Queue.new

    Sync do |task|
      acceptor = task.async { wrapper.accept(listener, transport: "tcp") { |socket, _| accepted << true and socket.close } }
      client = Socket.tcp("127.0.0.1", listener.local_address.ip_port)
      accepted.pop(timeout: 3) || false
    ensure
      client&.close
      acceptor&.stop
    end
  ensure
    listener&.close
  end

  def capture_console
    capture = Console::Capture.new
    previous = Console.logger
    Console.logger = Console::Logger.new(capture, level: :debug)
    yield
    capture.map(&:inspect).join("\n")
  ensure
    Console.logger = previous
  end

  def test_accept_goes_on_after_running_out_of_file_descriptors
    logged = capture_console { assert accept_once_after(Errno::EMFILE.new), "accepted once the descriptor is back" }
    assert_match(/server\.accept_failed/, logged)
  end

  def test_accept_skips_a_connection_aborted_before_accept
    logged = capture_console { assert accept_once_after(Errno::ECONNABORTED.new), "accepted the next connection" }
    refute_match(/server\.accept_failed/, logged)
  end

  def test_start_records_the_zone_and_zeroes_the_query_series
    with_server do |server|
      metrics = server.metrics
      assert_equal 2026092301, metrics.value("dohyo_zone_serial")
      assert_in_delta Time.now.to_f, metrics.value("dohyo_zone_loaded_timestamp_seconds"), 60
      assert_equal 0, metrics.value("dohyo_queries_total", transport: "dot", qtype: "A", rcode: "SERVFAIL")
      assert_equal 1, metrics.value("dohyo_build_info", version: Dohyo::VERSION, ruby: RUBY_VERSION)
    end
  end

  def test_connections_are_counted
    with_server do |server|
      tcp_exchange(address_of(server, "tcp"), query_bytes("blog.example.com.", IN::A))
      metrics = server.metrics
      deadline = monotonic + 1
      sleep 0.01 until metrics.value("dohyo_connections_active", transport: "tcp").to_i.zero? || monotonic > deadline

      assert_equal 1, metrics.value("dohyo_connections_opened_total", transport: "tcp")
      assert_equal 1, metrics.value("dohyo_connections_closed_total", transport: "tcp", reason: "peer")
      assert_equal 0, metrics.value("dohyo_connections_active", transport: "tcp")
    end
  end

  def test_idle_tcp_and_dot_connections_are_closed
    with_server(idle_timeout: 1) do |server|
      tcp = address_of(server, "tcp")
      socket = Socket.tcp(tcp.ip_address, tcp.ip_port)
      assert_equal 1, stream_exchange(socket, [query_bytes("blog.example.com.", IN::A)]).size

      dot = dot_connect(address_of(server, "dot"))
      assert_equal 1, stream_exchange(dot, [query_bytes("blog.example.com.", IN::A)]).size

      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      assert_nil socket.read(1), "TCP closed by the server"
      assert_nil dot.read(1), "DoT closed by the server"
      assert_in_delta 1, Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, 0.9
    ensure
      socket&.close
      dot&.close
    end
  end

  def monotonic = Process.clock_gettime(Process::CLOCK_MONOTONIC)

  def test_shutdown_closes_waiting_connections_at_once_and_stops_listening
    with_server do |server|
      tcp = address_of(server, "tcp")
      waiting = Socket.tcp(tcp.ip_address, tcp.ip_port)
      assert_equal 1, stream_exchange(waiting, [query_bytes("blog.example.com.", IN::A)]).size
      waiting_dot = dot_connect(address_of(server, "dot"))
      assert_equal 1, stream_exchange(waiting_dot, [query_bytes("blog.example.com.", IN::A)]).size

      started = monotonic
      server.shutdown(grace: 5)
      assert_operator monotonic - started, :<, 1, "nothing was in progress, so no need to wait"

      assert_nil waiting.read(1)
      assert_nil waiting_dot.read(1)
      assert_raises(Errno::ECONNREFUSED) { Socket.tcp(tcp.ip_address, tcp.ip_port) }
    ensure
      waiting&.close
      waiting_dot&.close
    end
  end

  def test_shutdown_drops_a_connection_mid_query_after_the_grace_period
    with_server do |server|
      tcp = address_of(server, "tcp")
      socket = Socket.tcp(tcp.ip_address, tcp.ip_port)
      bytes = query_bytes("blog.example.com.", IN::A)
      socket.write([bytes.bytesize].pack("n") + bytes.byteslice(0, 5))
      sleep 0.05 # Let the server read the length and start waiting for the rest.

      started = monotonic
      server.shutdown(grace: 0.3)
      assert_in_delta 0.3, monotonic - started, 0.2
      assert_nil socket.read(1)
    ensure
      socket&.close
    end
  end

  def test_queries_are_counted_per_transport
    with_server do |server|
      udp_exchange(address_of(server, "udp"), query_bytes("big.blog.example.com.", IN::A))
      tcp_exchange(address_of(server, "tcp"), query_bytes("nope.blog.example.com.", IN::AAAA))
      dot_exchange(address_of(server, "dot"), query_bytes("blog.example.com.", IN::HTTPS))
      socket = Socket.new(:INET, :DGRAM)
      socket.send("short".b, 0, address_of(server, "udp").to_sockaddr)

      metrics = server.metrics
      assert_equal 1, metrics.value("dohyo_queries_total", transport: "udp", qtype: "A", rcode: "NOERROR")
      assert_equal 1, metrics.value("dohyo_responses_truncated_total")
      assert_equal 1, metrics.value("dohyo_queries_total", transport: "tcp", qtype: "AAAA", rcode: "NXDOMAIN")
      assert_equal 1, metrics.value("dohyo_queries_total", transport: "dot", qtype: "HTTPS", rcode: "NOERROR")
      sleep 0.05
      assert_equal 1, metrics.value("dohyo_queries_dropped_total", transport: "udp", reason: "too_short")
      assert_match(/^dohyo_query_duration_seconds_count\{transport="dot"\} 1$/, metrics.render)
    ensure
      socket&.close
    end
  end

  def test_several_queries_on_one_tcp_connection
    with_server do |server|
      responses = tcp_exchange(address_of(server, "tcp"),
        query_bytes("blog.example.com.", IN::A, id: 1), query_bytes("blog.example.com.", IN::AAAA, id: 2))
      assert_equal [1, 2], responses.map { Resolv::DNS::Message.decode(it).id }
    end
  end

  def test_undecodable_query_over_udp_is_formerr
    with_server do |server|
      bytes = query_bytes("blog.example.com.", IN::A)
      response = udp_exchange(address_of(server, "udp"), bytes.byteslice(0, bytes.bytesize - 3))
      assert_equal [4242, Resolv::DNS::RCode::FormErr], header_of(response).values_at(:id, :rcode)
    end
  end

  # IPV6_V6ONLY: "[::]" must not take the IPv4 side of the port, so both can be bound at once.
  def test_ipv4_and_ipv6_wildcards_share_a_port
    wrapper = Dohyo::Server::Wrapper.new
    v4 = wrapper.bind(Addrinfo.udp("0.0.0.0", 0))
    port = v4.local_address.ip_port
    v6 = wrapper.bind(Addrinfo.udp("::", port))

    assert_equal port, v6.local_address.ip_port
    assert v6.getsockopt(Socket::IPPROTO_IPV6, Socket::IPV6_V6ONLY).bool
  ensure
    v4&.close
    v6&.close
  end

  def test_kdig
    skip "kdig is not installed" unless system("which kdig", out: File::NULL, err: File::NULL)

    with_server do |server|
      udp = address_of(server, "udp")
      tcp = address_of(server, "tcp")

      output = kdig("@#{udp.ip_address}", "-p", udp.ip_port.to_s, "blog.example.com", "HTTPS")
      assert_match(/status: NOERROR/, output)
      assert_match(/alpn="?h3,h2"?/, output)

      output = kdig("@#{tcp.ip_address}", "-p", tcp.ip_port.to_s, "+tcp", "big.blog.example.com", "A")
      assert_equal 40, output.scan(/\bIN\s+A\s+192\.0\.2\./).size

      dot = address_of(server, "dot")
      tls = ["@#{dot.ip_address}", "-p", dot.ip_port.to_s, "+tls-ca=#{@certificates.ca}", "+tls-hostname=localhost"]
      output = kdig(*tls, "big.blog.example.com", "A")
      assert_match(/TLS session \(TLS1\.3\)/, output)
      assert_equal 40, output.scan(/\bIN\s+A\s+192\.0\.2\./).size

      output = kdig(*tls, "+keepopen", "blog.example.com", "A", "blog.example.com", "AAAA")
      assert_match(/192\.0\.2\.1/, output)
      assert_match(/2001:db8::1/, output)
    end
  end

  private

  # kdig blocks, so it runs in a thread while the reactor keeps serving.
  def kdig(*arguments)
    Thread.new { Open3.capture2e("kdig", "+retry=0", "+timeout=3", *arguments).first }.value
  end
end
