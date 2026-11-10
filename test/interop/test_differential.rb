# frozen_string_literal: true

require "test_helper"
require "async"
require "yaml"
require "support/rfc8906"
require_relative "support/knotd"

# Sends the queries of cases 1-28 (test_responder.rb, test_engine.rb) and R1-R14 (support/rfc8906.rb) to dohyo and to
# Knot DNS as raw bytes over UDP and TCP, and compares the answers: the RCODE (with the extended bits of the OPT), AA,
# TC, and each section as a set of RRs with their TTLs. IDs and the order of RRs are not compared.
#
# Knot DNS is not the reference. Each difference is decided by the RFCs: dohyo's mistakes are fixed, and Knot DNS's
# mistakes and choices dohyo makes on its own go in differential_exclusions.yml with the reason and the RFC.
class TestInteropDifferential < Minitest::Test
  include DohyoTestHelper

  EXCLUSIONS = File.expand_path("differential_exclusions.yml", __dir__)
  FIELDS = %i[rcode aa tc answer authority additional].freeze
  NO_ANSWER_TIMEOUT = 1
  UDP_PAYLOAD_SIZE = 1232

  Row = Data.define(:id, :bytes, :transports)

  def self.row(id, bytes, transports: %i[udp tcp]) = Row.new(id:, bytes:, transports:)

  # The rows build their queries with the same helpers as the unit tests.
  extend DohyoTestHelper

  ZONE = "blog.example.com."
  BIG = "big.blog.example.com."
  def self.type(number, klass = IN::ClassValue) = Resolv::DNS::Resource.get_class(number, klass)

  ROWS = [
    row("1", query_bytes(ZONE, IN::SOA)),
    row("2", query_bytes(ZONE, IN::NS)),
    row("3", query_bytes(ZONE, IN::A)),
    row("4", query_bytes(ZONE, IN::AAAA)),
    row("5", query_bytes(ZONE, IN::HTTPS)),
    row("6", query_bytes("BLOG.EXAMPLE.COM.", IN::A)),
    row("7", query_bytes(ZONE, IN::MX)),
    row("8", query_bytes(ZONE, type(43))),
    row("9", query_bytes("nope.#{ZONE}", IN::A)),
    row("10", query_bytes("y.#{ZONE}", IN::A)),
    row("11", query_bytes("x.y.#{ZONE}", IN::A)),
    row("12", query_bytes(ZONE, IN::ANY)),
    row("13", query_bytes("y.#{ZONE}", IN::ANY)),
    row("14", query_bytes("example.com.", IN::A)),
    row("15", query_bytes("example.org.", IN::A)),
    row("16-axfr", query_bytes(ZONE, type(252))),
    row("16-ixfr", query_bytes(ZONE, type(251))),
    row("17", query_bytes("version.bind.", type(16, 3))),
    row("18-notify", query_bytes(ZONE, IN::SOA, opcode: Resolv::DNS::OpCode::Notify)),
    row("18-status", query_bytes(ZONE, IN::SOA, opcode: 2)),
    row("19-none", query_bytes(nil, nil)),
    row("19-two", query_message(ZONE, IN::A).tap { it.add_question(ZONE, IN::AAAA) }.encode),
    row("20", query_bytes(ZONE, IN::A).then { it.byteslice(0, it.bytesize - 3) }),
    row("21-short", "\x00\x01\x00".b),
    row("21-response", query_message(ZONE, IN::A).tap { it.qr = 1 }.encode),
    row("22", query_bytes(ZONE, IN::A, edns: 4096)),
    row("23", query_bytes(ZONE, IN::A, edns: 4096, edns_ttl: 1 << 16)),
    row("24", query_bytes(ZONE, IN::A, edns: 4096, edns_count: 2)),
    row("25", query_bytes(BIG, IN::A)),
    row("26", query_bytes(BIG, IN::A, edns: 1232)),
    row("27", query_bytes(BIG, IN::A, edns: 512)),
    row("28", query_bytes(BIG, IN::A), transports: %i[tcp]),
    *RFC8906::ROWS.values.map do |r|
      row(r.id.to_s.upcase, r.bytes, transports: r.transports.map { (it == :stream) ? :tcp : it })
    end
  ].freeze

  def setup
    skip "knotd is not installed" unless Knotd.installed?
  end

  def test_answers_match_knot_dns_except_the_exclusions
    exclusions = load_exclusions
    differences = []
    unused = exclusions.keys.to_set

    Knotd.run(origin: ORIGIN, path: FIXTURE, udp_payload_size: UDP_PAYLOAD_SIZE) do |knotd|
      with_dohyo do |dohyo|
        ROWS.each do |row|
          row.transports.each do |transport|
            ours = summarize(exchange(dohyo.fetch(transport), row.bytes, transport))
            theirs = summarize(exchange(knotd.address, row.bytes, transport))
            differ = FIELDS.reject { ours&.fetch(it) == theirs&.fetch(it) }
            differ = FIELDS if ours.nil? != theirs.nil?

            ignored = exclusions.fetch(row.id, [])
            unused.delete(row.id) if differ.intersect?(ignored)
            next if (differ - ignored).empty?

            differences << describe(row, transport, differ - ignored, ours, theirs)
          end
        end
      end
    end

    assert_empty differences, differences.join("\n\n")
    assert_empty unused.to_a, "exclusions that no longer exclude anything"
  end

  private

  # Row ID to the fields not compared. Each entry needs a reason and the RFC behind it.
  def load_exclusions
    YAML.safe_load_file(EXCLUSIONS).each_with_object({}) do |entry, exclusions|
      id, ignore, reason, rfc = entry.values_at("id", "ignore", "reason", "rfc")
      ignore = ignore.map(&:to_sym)
      raise "#{EXCLUSIONS}: unknown row #{id}" unless ROWS.any? { it.id == id }
      raise "#{EXCLUSIONS}: #{id}: unknown fields #{ignore - FIELDS}" unless (ignore - FIELDS).empty?
      raise "#{EXCLUSIONS}: #{id}: a reason and an RFC are required" if reason.to_s.empty? || rfc.to_s.empty?
      raise "#{EXCLUSIONS}: #{id} appears more than once" if exclusions.key?(id)

      exclusions[id] = ignore
    end
  end

  def with_dohyo
    listen = %w[udp://127.0.0.1:0 tcp://127.0.0.1:0].map { Dohyo::Server::Listen.parse(it) }

    Sync do |task|
      server = Dohyo::Server.new(zone: fixture_zone, listen:, udp_payload_size: UDP_PAYLOAD_SIZE, max_connections: 16, idle_timeout: 10, tls: nil)
      server.start(task)
      addresses = server.bound_addresses.to_h { |transport, address| [transport.to_sym, address] }
      yield addresses
    ensure
      server&.stop
    end
  end

  # @returns [String, nil] The response, or nil when nothing came back within NO_ANSWER_TIMEOUT.
  def exchange(address, bytes, transport)
    if transport == :udp
      socket = Socket.new(:INET, :DGRAM)
      socket.send(bytes, 0, Addrinfo.udp(address.ip_address, address.ip_port))
      socket.wait_readable(NO_ANSWER_TIMEOUT) ? socket.recv(65535) : nil
    else
      socket = Socket.tcp(address.ip_address, address.ip_port)
      socket.write([bytes.bytesize].pack("n") + bytes)
      return nil unless socket.wait_readable(NO_ANSWER_TIMEOUT)

      length = socket.read(2)&.unpack1("n")
      length && socket.read(length)
    end
  rescue Errno::ECONNRESET, Errno::EPIPE
    nil
  ensure
    socket&.close
  end

  # The fields compared, from the wire. resolv stops decoding after the header when TC=1, so the bit is cleared first.
  def summarize(bytes)
    return nil if bytes.nil?

    header = header_of(bytes)
    flags = bytes.unpack1("x2n") & ~0x0200
    message = Resolv::DNS::Message.decode(bytes.byteslice(0, 2) + [flags].pack("n") + bytes.byteslice(4..))
    opt = message.additional.find { |_, _, record| record.class::TypeValue == 41 }
    extended = opt ? (opt[1] >> 24) << 4 : 0

    {
      rcode: extended | header[:rcode], aa: header[:aa], tc: header[:tc],
      answer: rr_set(message.answer), authority: rr_set(message.authority), additional: rr_set(message.additional)
    }
  end

  def rr_set(section)
    section.map do |name, ttl, record|
      type = record.class::TypeValue
      klass = record.class::ClassValue
      "#{name}. #{ttl} #{klass} #{type} #{Dohyo::Zone.rdata(record).unpack1("H*")}"
    end.sort
  end

  def describe(row, transport, fields, ours, theirs)
    lines = ["row #{row.id} over #{transport}: #{fields.join(", ")}"]
    return (lines << "  dohyo: #{ours.inspect}" << "  knotd: #{theirs.inspect}").join("\n") if ours.nil? || theirs.nil?

    fields.each do |field|
      lines << "  #{field}:" << "    dohyo: #{ours.fetch(field).inspect}" << "    knotd: #{theirs.fetch(field).inspect}"
    end
    lines.join("\n")
  end
end
