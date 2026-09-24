# frozen_string_literal: true

require "test_helper"

class TestEDNS < Minitest::Test
  include DohyoTestHelper

  def round_trip(message)
    Resolv::DNS::Message.decode(message.encode)
  end

  def test_extract_returns_nil_without_opt
    assert_nil Dohyo::EDNS.extract(query_message("blog.example.com.", IN::A))
  end

  def test_extract_splits_class_and_ttl
    ttl = (3 << 24) | (1 << 16) | 0x8000
    options = [10, 8].pack("nn") + "cookie!!".b + [11, 0].pack("nn")
    message = round_trip(query_message("blog.example.com.", IN::A, edns: 4096, edns_ttl: ttl, edns_data: options))

    opt = Dohyo::EDNS.extract(message)
    assert_equal 4096, opt.udp_payload_size
    assert_equal 3, opt.extended_rcode
    assert_equal 1, opt.version
    assert opt.dnssec_ok
    assert_equal [[10, "cookie!!".b], [11, "".b]], opt.options
    assert_equal [10, 11], opt.option_codes
  end

  def test_extract_ignores_a_truncated_trailing_option
    options = [10, 8].pack("nn") + "abc".b
    message = round_trip(query_message("blog.example.com.", IN::A, edns: 1232, edns_data: options))
    assert_empty Dohyo::EDNS.extract(message).options
  end

  def test_append_round_trips
    message = Resolv::DNS::Message.new(1)
    Dohyo::EDNS.append(message, udp_payload_size: 1232, rcode: 0)

    opt = Dohyo::EDNS.extract(round_trip(message))
    assert_equal 1232, opt.udp_payload_size
    assert_equal 0, opt.extended_rcode
    assert_equal 0, opt.version
    refute opt.dnssec_ok
    assert_empty opt.options
  end

  def test_append_splits_badvers_between_header_and_opt
    message = Resolv::DNS::Message.new(1)
    Dohyo::EDNS.append(message, udp_payload_size: 1232, rcode: 16)

    decoded = round_trip(message)
    assert_equal 0, decoded.rcode
    assert_equal 1, Dohyo::EDNS.extract(decoded).extended_rcode
  end

  def test_count
    message = query_message("blog.example.com.", IN::A, edns: 1232, edns_count: 2)
    assert_equal 2, Dohyo::EDNS.count(round_trip(message))
  end
end
