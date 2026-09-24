# frozen_string_literal: true

require "test_helper"
require "async"
require "async/dns"

# Starts Dohyo::Server on loopback ports chosen by the OS and queries it over real sockets.
class TestServerIntegration < Minitest::Test
  include DohyoTestHelper

  LISTEN = %w[udp://127.0.0.1:0 tcp://127.0.0.1:0 udp://[::1]:0 tcp://[::1]:0].freeze

  def with_server(listen: LISTEN)
    Sync do |task|
      server = Dohyo::Server.new(zone: fixture_zone, listen: listen.map { Dohyo::Server::Listen.parse(it) }, udp_payload_size: 1232)
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
    messages.map do |bytes|
      socket.write([bytes.bytesize].pack("n"), bytes)
      length = socket.read(2).unpack1("n")
      socket.read(length)
    end
  ensure
    socket&.close
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
end
