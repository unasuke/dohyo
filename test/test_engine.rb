# frozen_string_literal: true

require "test_helper"

# Cases 14-28, numbered on from test_responder.rb: refusals, malformed queries, EDNS(0), UDP truncation and a large
# answer over a stream, through Engine#call with raw bytes.
class TestEngine < Minitest::Test
  include DohyoTestHelper

  def setup
    zone = fixture_zone
    @engine = Dohyo::Engine.new(zone_provider: -> { zone }, udp_payload_size: 1232)
  end

  def call(bytes, transport: :udp)
    @engine.call(bytes, transport:)
  end

  def decode(result)
    Resolv::DNS::Message.decode(result.bytes)
  end

  def opt_of(message)
    message.additional.find { |_, _, record| record.class::TypeValue == 41 }
  end

  def assert_error_header(result, rcode, id: 4242)
    header = header_of(result.bytes)
    assert_equal id, header[:id]
    assert_equal 1, header[:qr]
    assert_equal 0, header[:aa]
    assert_equal 0, header[:tc]
    assert_equal rcode, header[:rcode]
    assert_equal 0, header[:ancount]
    assert_equal 0, header[:nscount]
    header
  end

  def test_case_14_name_above_the_apex_is_refused
    result = call(query_bytes("example.com.", IN::A))
    assert_equal "REFUSED", result.rcode
    header = assert_error_header(result, Resolv::DNS::RCode::Refused)
    assert_equal 1, header[:qdcount]
  end

  def test_case_15_name_outside_the_zone_is_refused
    result = call(query_bytes("example.org.", IN::A))
    assert_equal "REFUSED", result.rcode
    assert_error_header(result, Resolv::DNS::RCode::Refused)
  end

  def test_a_label_with_a_dot_ending_like_the_zone_is_refused
    # The labels "x.blog", "example" and "com": below example.com., not below blog.example.com.
    labels = [Resolv::DNS::Label::Str.new("x.blog"), *Resolv::DNS::Name.create("example.com.").to_a]
    result = call(query_bytes(Resolv::DNS::Name.new(labels, true), IN::A))
    assert_equal "REFUSED", result.rcode
    assert_error_header(result, Resolv::DNS::RCode::Refused)
  end

  def test_case_16_axfr_is_refused
    result = call(query_bytes("blog.example.com.", Resolv::DNS::Resource.get_class(252, IN::ClassValue)))
    assert_equal "REFUSED", result.rcode
    assert_error_header(result, Resolv::DNS::RCode::Refused)
  end

  def test_case_16_ixfr_is_refused
    result = call(query_bytes("blog.example.com.", Resolv::DNS::Resource.get_class(251, IN::ClassValue)))
    assert_equal "REFUSED", result.rcode
  end

  def test_case_17_class_ch_is_refused
    result = call(query_bytes("version.bind.", Resolv::DNS::Resource.get_class(16, 3)))
    assert_equal "REFUSED", result.rcode
    assert_error_header(result, Resolv::DNS::RCode::Refused)
  end

  def test_case_18_notify_is_notimp
    result = call(query_bytes("blog.example.com.", IN::SOA, opcode: Resolv::DNS::OpCode::Notify))
    assert_equal "NOTIMP", result.rcode
    header = assert_error_header(result, Resolv::DNS::RCode::NotImp)
    assert_equal Resolv::DNS::OpCode::Notify, header[:opcode]
  end

  def test_case_18_status_is_notimp
    result = call(query_bytes("blog.example.com.", IN::SOA, opcode: 2))
    assert_equal "NOTIMP", result.rcode
  end

  def test_case_19_no_question_is_formerr
    result = call(query_bytes(nil, nil))
    assert_equal "FORMERR", result.rcode
    header = assert_error_header(result, Resolv::DNS::RCode::FormErr)
    assert_equal 0, header[:qdcount]
  end

  def test_case_19_two_questions_is_formerr
    message = query_message("blog.example.com.", IN::A)
    message.add_question("blog.example.com.", IN::AAAA)
    result = call(message.encode)
    assert_equal "FORMERR", result.rcode
    assert_error_header(result, Resolv::DNS::RCode::FormErr)
  end

  def test_case_20_truncated_question_is_formerr_with_the_same_id
    bytes = query_bytes("blog.example.com.", IN::A)
    result = call(bytes.byteslice(0, bytes.bytesize - 3))
    assert_equal "FORMERR", result.rcode
    header = assert_error_header(result, Resolv::DNS::RCode::FormErr)
    assert_equal 0, header[:qdcount]
    assert_equal 1, header[:rd]
  end

  def test_case_21_short_message_is_dropped
    result = call("\x00\x01\x00".b)
    assert_nil result.bytes
    assert_equal :too_short, result.dropped_reason
  end

  def test_case_21_response_is_dropped
    message = query_message("blog.example.com.", IN::A)
    message.qr = 1
    result = call(message.encode)
    assert_nil result.bytes
    assert_equal :is_response, result.dropped_reason
  end

  def test_case_22_opt_is_answered_with_our_payload_size
    result = call(query_bytes("blog.example.com.", IN::A, edns: 4096))
    response = decode(result)
    assert_equal "NOERROR", result.rcode
    assert_equal 1, response.aa
    assert_equal ["192.0.2.1"], response.answer.map { it[2].address.to_s }

    name, ttl, opt = opt_of(response)
    assert_equal "", name.to_s
    assert_equal 1232, opt.class::ClassValue
    assert_equal 0, ttl, "version 0, DO=0, extended RCODE 0"
    assert_equal "", opt.data
    assert_equal 1, response.additional.size
  end

  def test_case_23_opt_version_1_is_badvers
    result = call(query_bytes("blog.example.com.", IN::A, edns: 4096, edns_ttl: 1 << 16))
    assert_equal "BADVERS", result.rcode
    header = assert_error_header(result, 0)
    assert_equal 1, header[:arcount]

    _, ttl, opt = opt_of(decode(result))
    assert_equal 1, ttl >> 24, "the upper 8 bits of BADVERS (16)"
    assert_equal 0, (ttl >> 16) & 0xff, "version 0"
    assert_equal 1232, opt.class::ClassValue
  end

  def test_case_24_two_opts_is_formerr
    result = call(query_bytes("blog.example.com.", IN::A, edns: 4096, edns_count: 2))
    assert_equal "FORMERR", result.rcode
    assert_error_header(result, Resolv::DNS::RCode::FormErr)
  end

  def test_case_25_big_answer_over_udp_without_opt_is_truncated
    result = call(query_bytes("big.blog.example.com.", IN::A))
    assert result.truncated
    header = header_of(result.bytes)
    assert_equal [1, 1, 1, 0], header.values_at(:qr, :tc, :aa, :rcode)
    assert_equal [1, 0, 0, 0], header.values_at(:qdcount, :ancount, :nscount, :arcount)
    assert_operator result.bytes.bytesize, :<=, 512
  end

  def test_case_26_big_answer_fits_in_1232
    result = call(query_bytes("big.blog.example.com.", IN::A, edns: 1232))
    refute result.truncated
    response = decode(result)
    assert_equal 0, response.tc
    assert_equal 40, response.answer.size
    assert_equal 689, result.bytes.bytesize
  end

  def test_case_27_big_answer_over_udp_with_opt_512_is_truncated_but_keeps_opt
    result = call(query_bytes("big.blog.example.com.", IN::A, edns: 512))
    assert result.truncated
    header = header_of(result.bytes)
    assert_equal [1, 1, 0], header.values_at(:tc, :qdcount, :ancount)
    assert_equal 1, header[:arcount]
  end

  def test_case_28_big_answer_over_a_stream_is_not_truncated
    result = call(query_bytes("big.blog.example.com.", IN::A), transport: :stream)
    refute result.truncated
    assert_equal 40, decode(result).answer.size
  end

  def test_unknown_opcode_with_two_questions_is_notimp_without_the_question
    message = query_message("blog.example.com.", IN::SOA, opcode: 15)
    message.add_question("blog.example.com.", IN::A)
    result = call(message.encode)
    assert_equal "NOTIMP", result.rcode
    header = assert_error_header(result, Resolv::DNS::RCode::NotImp)
    assert_equal [15, 0], header.values_at(:opcode, :qdcount)
  end

  def test_unknown_opcode_keeps_one_opt_and_drops_two
    one = call(query_bytes("blog.example.com.", IN::SOA, opcode: 15, edns: 4096))
    assert_equal "NOTIMP", one.rcode
    assert_equal [1, 1], header_of(one.bytes).values_at(:qdcount, :arcount)

    two = call(query_bytes("blog.example.com.", IN::SOA, opcode: 15, edns: 4096, edns_count: 2))
    assert_equal "NOTIMP", two.rcode
    assert_equal [1, 0], header_of(two.bytes).values_at(:qdcount, :arcount)
  end

  def test_client_payload_size_below_512_is_raised_to_512
    result = call(query_bytes("blog.example.com.", IN::A, edns: 100))
    refute result.truncated
  end

  def test_our_payload_size_caps_a_larger_client_size
    zone = fixture_zone
    engine = Dohyo::Engine.new(zone_provider: -> { zone }, udp_payload_size: 600)
    result = engine.call(query_bytes("big.blog.example.com.", IN::A, edns: 4096), transport: :udp)
    assert result.truncated
  end

  def test_result_carries_the_question_and_edns_option_codes
    option = [11, 0].pack("nn")
    result = call(query_bytes("blog.example.com.", IN::AAAA, edns: 1232, edns_data: option))
    assert_equal "blog.example.com", result.qname
    assert_equal 28, result.qtype
    assert_equal [11], result.edns_option_codes
  end

  def test_unexpected_error_is_servfail_and_reported
    broken = Object.new
    def broken.contains?(_) = raise("boom")
    engine = Dohyo::Engine.new(zone_provider: -> { broken }, udp_payload_size: 1232)
    result = engine.call(query_bytes("blog.example.com.", IN::A), transport: :udp)

    assert_equal "SERVFAIL", result.rcode
    assert_equal "boom", result.error.message
    header = header_of(result.bytes)
    assert_equal [0, 1, Resolv::DNS::RCode::ServFail], header.values_at(:aa, :qdcount, :rcode)
  end

  def test_rejects_an_unknown_transport
    assert_raises(ArgumentError) { call(query_bytes("blog.example.com.", IN::A), transport: :tcp) }
  end
end
