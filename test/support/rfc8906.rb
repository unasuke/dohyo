# frozen_string_literal: true

require "resolv"

# The checks of RFC 8906 §8.1 and §8.2 that apply to dohyo, numbered R1-R14 in the order of the RFC, with the
# responses expected of dohyo. Shared by the unit and integration tests.
#
# §8.2.1 and §8.2.2 (plain EDNS, and EDNS version 1) are left out: the EDNS tests of Engine already cover them.
# §8.2.7 (DO=1 with an unknown option) needs a signed zone.
#
# Each query asks for the SOA of the apex. Header flags are 0 unless a row says otherwise; the unknown EDNS option
# is code 100 and the unknown EDNS flag 0x40. dohyo does not support DNSSEC, so CD, AD and DO are always 0 in its
# responses (RFC 8906 §8.1.3.1, RFC 3225 §3).
module RFC8906
  APEX = "blog.example.com."
  SERIAL = 2026092301
  UDP_PAYLOAD_SIZE = 1232

  # Header bits that resolv cannot set or read (RFC 1035 §4.1.1, RFC 4035 §3.2).
  RD = 0x0100
  Z = 0x0040
  AD = 0x0020
  CD = 0x0010

  # EDNS flags in the OPT TTL (RFC 6891 §6.1.3).
  DO = 0x8000
  UNKNOWN_EDNS_FLAG = 0x40
  UNKNOWN_OPTION = 100

  # The options of §8.2.10: NSID (RFC 5001), COOKIE with a client cookie only (RFC 7873), ECS for 0.0.0.0/0
  # (RFC 7871) and EXPIRE (RFC 7314).
  KNOWN_OPTIONS = [
    [3, "".b],
    [10, "\x01\x02\x03\x04\x05\x06\x07\x08".b],
    [8, [1, 0, 0].pack("nCC")],
    [9, "".b]
  ].freeze

  NOERROR = 0
  NOTIMP = 4
  BADVERS = 16

  # @attribute transports [Array<Symbol>] The Engine transports the row is sent over.
  # @attribute opcode [Integer] The opcode of the response.
  # @attribute rd [Integer] RD of the response, copied from the query.
  # @attribute question [Boolean] Whether the response carries the question.
  # @attribute answer [Symbol] :soa (the apex SOA) or :empty.
  # @attribute authority [Symbol] :soa (the apex SOA with the negative TTL) or :empty.
  # @attribute opt [Boolean] Whether the response carries an OPT: version 0, no flags, no options.
  Row = Data.define(:id, :description, :bytes, :transports, :rcode, :aa, :opcode, :rd, :question, :answer, :authority, :opt)

  module_function

  # A query for the apex. `flags` are ORed into the header; `edns_version` adds an OPT.
  def query(id, type_class: Resolv::DNS::Resource::IN::SOA, flags: 0, edns_version: nil, edns_flags: 0, options: [])
    message = Resolv::DNS::Message.new(id)
    message.rd = 0
    message.add_question(APEX, type_class)
    if edns_version
      data = options.map { |code, value| [code, value.bytesize].pack("nn") + value }.join.b
      opt = Resolv::DNS::Resource.get_class(41, UDP_PAYLOAD_SIZE).new(data)
      message.add_additional(Resolv::DNS::Name.create("."), (edns_version << 16) | edns_flags, opt)
    end

    bytes = message.encode
    header_flags = bytes.unpack1("n", offset: 2)
    bytes[2, 2] = [header_flags | flags].pack("n")
    bytes
  end

  def row(number, description, bytes, transports: %i[udp stream], rcode: NOERROR, aa: 1, opcode: 0, rd: 0, question: true, answer: :soa, authority: :empty, opt: false)
    Row.new(id: :"r#{number}", description:, bytes:, transports:, rcode:, aa:, opcode:, rd:, question:, answer:, authority:, opt:)
  end

  # IDs are 8900 + the row number, so that a response cannot be taken for another row's.
  ROWS = [
    row(1, "TYPE1000 without EDNS (§8.1.2)",
      query(8901, type_class: Resolv::DNS::Resource.get_class(1000, Resolv::DNS::Resource::IN::ClassValue)),
      answer: :empty, authority: :soa),
    row(2, "CD=1 without EDNS (§8.1.3.1)", query(8902, flags: CD)),
    row(3, "AD=1 without EDNS (§8.1.3.2)", query(8903, flags: AD)),
    row(4, "Z=1 without EDNS (§8.1.3.3)", query(8904, flags: Z)),
    row(5, "RD=1 without EDNS (§8.1.3.4)", query(8905, flags: RD), rd: 1),
    row(6, "header only, opcode 15 (§8.1.4)", [8906, 15 << 11, 0, 0, 0, 0].pack("n6"),
      rcode: NOTIMP, aa: 0, opcode: 15, question: false, answer: :empty),
    row(7, "TCP without EDNS (§8.1.5)", query(8907), transports: %i[stream]),
    row(8, "EDNS 0 with option 100 (§8.2.3)", query(8908, edns_version: 0, options: [[UNKNOWN_OPTION, "".b]]), opt: true),
    row(9, "EDNS 0 with flag 0x40 (§8.2.4)", query(8909, edns_version: 0, edns_flags: UNKNOWN_EDNS_FLAG), opt: true),
    row(10, "EDNS 1 with flag 0x40 (§8.2.5)", query(8910, edns_version: 1, edns_flags: UNKNOWN_EDNS_FLAG),
      rcode: BADVERS, aa: 0, answer: :empty, opt: true),
    row(11, "EDNS 1 with option 100 (§8.2.6)", query(8911, edns_version: 1, options: [[UNKNOWN_OPTION, "".b]]),
      rcode: BADVERS, aa: 0, answer: :empty, opt: true),
    row(12, "EDNS 0 with DO=1 (§8.2.8)", query(8912, edns_version: 0, edns_flags: DO), opt: true),
    row(13, "EDNS 1 with DO=1 (§8.2.9)", query(8913, edns_version: 1, edns_flags: DO),
      rcode: BADVERS, aa: 0, answer: :empty, opt: true),
    row(14, "EDNS 0 with NSID, COOKIE, ECS and EXPIRE (§8.2.10)", query(8914, edns_version: 0, options: KNOWN_OPTIONS),
      opt: true)
  ].to_h { [it.id, it] }.freeze

  # Assertions on a response to a row, for Minitest::Test.
  module Assertions
    def assert_rfc8906_response(row, bytes, message = nil)
      label = [message, "R#{row.id.to_s.delete_prefix("r")} #{row.description}"].compact.join(": ")
      refute_nil bytes, "#{label}: no response"

      id, flags, qdcount, ancount, nscount, arcount = bytes.unpack("n6")
      assert_equal row.bytes.unpack1("n"), id, "#{label}: ID"
      expected_flags = {qr: 1, opcode: row.opcode, aa: row.aa, tc: 0, rd: row.rd, ra: 0, z: 0, ad: 0, cd: 0}
      actual_flags = {
        qr: flags[15], opcode: (flags >> 11) & 0xf, aa: flags[10], tc: flags[9], rd: flags[8], ra: flags[7],
        z: flags[6], ad: flags[5], cd: flags[4]
      }
      assert_equal expected_flags, actual_flags, "#{label}: header flags"
      assert_equal [row.question ? 1 : 0, row.opt ? 1 : 0], [qdcount, arcount], "#{label}: QDCOUNT and ARCOUNT"

      response = Resolv::DNS::Message.decode(bytes)
      if row.question
        assert_equal rfc8906_question(Resolv::DNS::Message.decode(row.bytes)), rfc8906_question(response), "#{label}: question"
      end
      assert_rfc8906_section(row.answer, response.answer, ancount, "#{label}: answer")
      assert_rfc8906_section(row.authority, response.authority, nscount, "#{label}: authority")

      extended_rcode = 0
      if row.opt
        name, ttl, opt = response.additional.first
        assert_equal [41, "", UDP_PAYLOAD_SIZE], [opt.class::TypeValue, name.to_s, opt.class::ClassValue], "#{label}: OPT"
        extended_rcode = ttl >> 24
        assert_equal 0, ttl & 0xffffff, "#{label}: OPT version 0 and no flags"
        assert_equal "".b, opt.data.b, "#{label}: OPT options"
      end
      assert_equal row.rcode, (extended_rcode << 4) | (flags & 0xf), "#{label}: RCODE"
    end

    private

    def rfc8906_question(message)
      message.question.map { |name, type_class| [name.to_s, type_class::TypeValue] }
    end

    def assert_rfc8906_section(expected, rrs, count, label)
      if expected == :empty
        assert_equal 0, count, label
      else
        assert_equal 1, count, label
        name, _, soa = rrs.first
        assert_equal [APEX.chomp("."), Resolv::DNS::Resource::IN::SOA, SERIAL], [name.to_s, soa.class, soa.serial], label
      end
    end
  end
end
