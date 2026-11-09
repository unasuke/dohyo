# frozen_string_literal: true

require "test_helper"

# Cases 1-13: the content of answers, NODATA and NXDOMAIN, asked of Responder directly.
#
# The cases are numbered across the test files: 1-13 here, 14-28 in test_engine.rb (28 also over DoT in
# integration/test_server.rb and over DoQ in integration/test_doq.rb), Q1-Q8 for DoQ in integration/test_doq.rb,
# and R1-R14 for RFC 8906 in support/rfc8906.rb.
class TestResponder < Minitest::Test
  include DohyoTestHelper

  def respond(name, type_class)
    Dohyo::Responder.new.call(query_message(name, type_class), fixture_zone)
  end

  def assert_answer(response, rcode: Resolv::DNS::RCode::NoError)
    assert_equal 1, response.qr
    assert_equal 1, response.aa
    assert_equal 0, response.ra
    assert_equal rcode, response.rcode
  end

  def test_case_01_apex_soa
    response = respond("blog.example.com.", IN::SOA)
    assert_answer(response)
    assert_equal 1, response.answer.size
    _, ttl, soa = response.answer.first
    assert_equal 3600, ttl
    assert_equal [2026092301, 7200, 3600, 1209600, 300], [soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum]
    assert_equal "ns.example.com", soa.mname.to_s
    assert_empty response.authority
  end

  def test_case_02_apex_ns_without_additional
    response = respond("blog.example.com.", IN::NS)
    assert_answer(response)
    assert_equal [["blog.example.com", 3600]], rrs(response.answer).map { it.take(2) }
    assert_equal "ns.example.com", response.answer.first[2].name.to_s
    assert_empty response.additional
  end

  def test_case_03_apex_a
    response = respond("blog.example.com.", IN::A)
    assert_answer(response)
    assert_equal ["192.0.2.1"], response.answer.map { it[2].address.to_s }
  end

  def test_case_04_apex_aaaa
    response = respond("blog.example.com.", IN::AAAA)
    assert_answer(response)
    assert_equal ["2001:db8::1"], response.answer.map { it[2].address.to_s }
  end

  def test_case_05_apex_https_round_trips
    response = Resolv::DNS::Message.decode(respond("blog.example.com.", IN::HTTPS).encode)
    assert_answer(response)
    _, ttl, https = response.answer.fetch(0)
    assert_equal 3600, ttl
    assert_equal 1, https.priority
    assert_equal "", https.target.to_s
    alpn = https.params.to_a.fetch(0)
    assert_instance_of Resolv::DNS::SvcParam::ALPN, alpn
    assert_equal %w[h3 h2], alpn.protocol_ids
  end

  def test_case_06_question_case_is_preserved
    response = Resolv::DNS::Message.decode(respond("BLOG.EXAMPLE.COM.", IN::A).encode)
    assert_answer(response)
    assert_equal "BLOG.EXAMPLE.COM", response.question.first[0].to_s
    assert_equal "BLOG.EXAMPLE.COM", response.answer.first[0].to_s
  end

  def test_case_07_unsupported_type_is_nodata
    response = respond("blog.example.com.", Resolv::DNS::Resource::IN::MX)
    assert_answer(response)
    assert_empty response.answer
    assert_negative_soa(response)
  end

  def test_case_08_ds_at_apex_is_nodata
    response = respond("blog.example.com.", Resolv::DNS::Resource.get_class(43, IN::ClassValue))
    assert_answer(response)
    assert_empty response.answer
    assert_negative_soa(response)
  end

  def test_case_09_missing_name_is_nxdomain
    response = respond("nope.blog.example.com.", IN::A)
    assert_answer(response, rcode: Resolv::DNS::RCode::NXDomain)
    assert_empty response.answer
    assert_negative_soa(response)
  end

  def test_case_10_empty_non_terminal_is_nodata
    response = respond("y.blog.example.com.", IN::A)
    assert_answer(response)
    assert_empty response.answer
    assert_negative_soa(response)
  end

  def test_case_11_name_below_empty_non_terminal
    response = respond("x.y.blog.example.com.", IN::A)
    assert_answer(response)
    assert_equal ["192.0.2.10"], response.answer.map { it[2].address.to_s }
  end

  def test_case_12_any_returns_the_smallest_type
    response = respond("blog.example.com.", IN::ANY)
    assert_answer(response)
    assert_equal [IN::A], response.answer.map { it[2].class }
    assert_equal ["192.0.2.1"], response.answer.map { it[2].address.to_s }
  end

  def test_case_13_any_at_empty_non_terminal_is_nodata
    response = respond("y.blog.example.com.", IN::ANY)
    assert_answer(response)
    assert_empty response.answer
    assert_negative_soa(response)
  end

  def test_rejects_a_name_outside_the_zone
    assert_raises(Dohyo::ProtocolError) { respond("example.org.", IN::A) }
  end
end
