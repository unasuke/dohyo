# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "dohyo"

require "minitest/autorun"

module DohyoTestHelper
  FIXTURE = File.expand_path("fixtures/blog.example.com.zone", __dir__)
  ORIGIN = "blog.example.com."

  IN = Resolv::DNS::Resource::IN

  def fixture_zone
    @fixture_zone ||= Dohyo::Loader.load(origin: ORIGIN, path: FIXTURE)
  end

  # Builds a query message. `edns:` adds an OPT with that UDP payload size; `edns_ttl:` overrides the OPT TTL.
  def query_message(name, type_class, id: 4242, opcode: Resolv::DNS::OpCode::Query, edns: nil, edns_ttl: 0, edns_count: 1, edns_data: "".b)
    message = Resolv::DNS::Message.new(id)
    message.rd = 1
    message.opcode = opcode
    message.add_question(name, type_class) if name
    if edns
      edns_count.times do
        message.add_additional(Resolv::DNS::Name.create("."), edns_ttl, Resolv::DNS::Resource.get_class(41, edns).new(edns_data))
      end
    end
    message
  end

  def query_bytes(...)
    query_message(...).encode
  end

  # Parses a response by hand where resolv cannot: Message.decode stops after the header when TC=1.
  def header_of(bytes)
    id, flags, qdcount, ancount, nscount, arcount = bytes.unpack("n6")
    {
      id:, qr: flags[15], opcode: (flags >> 11) & 0xf, aa: flags[10], tc: flags[9], rd: flags[8], ra: flags[7],
      rcode: flags & 0xf, qdcount:, ancount:, nscount:, arcount:
    }
  end

  def rrs(section)
    section.map { |name, ttl, record| [name.to_s, ttl, record] }
  end

  # Runs the block as under the C locale, where Ruby reads files as US-ASCII unless told otherwise.
  def with_c_locale
    verbose, $VERBOSE = $VERBOSE, nil
    previous = Encoding.default_external
    Encoding.default_external = Encoding::US_ASCII
    yield
  ensure
    Encoding.default_external = previous
    $VERBOSE = verbose
  end

  # Opens a TLS handshake and sends the ClientHello a byte every `interval` seconds, for at most `seconds`.
  # @returns [Float, nil] Seconds until the server closed the connection, or nil when it kept waiting.
  def trickle_client_hello(host, port, interval: 0.3, seconds: 4)
    socket = Socket.tcp(host, port)
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    # A handshake record announcing 512 bytes: the server reads on until all of them have arrived.
    socket.write("\x16\x03\x01\x02\x00".b)

    loop do
      elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
      return nil if elapsed > seconds
      return elapsed if socket.wait_readable(interval)

      socket.write("\x01".b)
    end
  rescue Errno::EPIPE, Errno::ECONNRESET
    Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
  ensure
    socket&.close
  end

  def assert_negative_soa(response)
    assert_equal 1, response.authority.size
    name, ttl, soa = response.authority.first
    assert_equal "blog.example.com", name.to_s
    assert_equal 300, ttl
    assert_instance_of IN::SOA, soa
    assert_equal 2026092301, soa.serial
  end
end
