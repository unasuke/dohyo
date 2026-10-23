# frozen_string_literal: true

require "test_helper"

class TestZone < Minitest::Test
  include DohyoTestHelper

  def test_key_normalizes_case_and_adds_the_trailing_dot
    assert_equal "blog.example.com.", Dohyo::Zone.key(Resolv::DNS::Name.create("BLOG.Example.com"))
    assert_equal ".", Dohyo::Zone.key(Resolv::DNS::Name.create("."))
  end

  def test_key_escapes_dots_inside_a_label
    name = Resolv::DNS::Name.new([Resolv::DNS::Label::Str.new("x.y"), *Resolv::DNS::Name.create("blog.example.com.").to_a], true)
    assert_equal "x\\.y.blog.example.com.", Dohyo::Zone.key(name)
    refute fixture_zone.name_exists?(Dohyo::Zone.key(name))
  end

  def test_apex_data
    zone = fixture_zone
    assert_equal "blog.example.com.", zone.origin
    assert_equal 2026092301, zone.serial
    assert_equal 300, zone.negative_ttl
    assert_equal [1, 2, 6, 28, 65], zone.types_at("blog.example.com.")
  end

  def test_negative_ttl_is_the_smaller_of_soa_ttl_and_minimum
    zone = Dohyo::Loader.parse(<<~ZONE, origin: ORIGIN)
      $ORIGIN blog.example.com.
      $TTL 3600
      @ 120 IN SOA ns.example.com. hostmaster.example.com. ( 1 7200 3600 1209600 300 )
      @ IN NS ns.example.com.
    ZONE
    assert_equal 120, zone.negative_ttl
  end

  def test_names_and_empty_non_terminals
    zone = fixture_zone
    assert zone.name_exists?("blog.example.com.")
    assert zone.name_exists?("x.y.blog.example.com.")
    assert zone.name_exists?("y.blog.example.com.")
    refute zone.name_exists?("nope.blog.example.com.")
    assert_empty zone.types_at("y.blog.example.com.")
  end

  def test_rrset
    ttl, records = fixture_zone.rrset("big.blog.example.com.", 1)
    assert_equal 3600, ttl
    assert_equal 40, records.size
    assert_nil fixture_zone.rrset("big.blog.example.com.", 28)
  end

  def test_contains
    zone = fixture_zone
    assert zone.contains?("blog.example.com.")
    assert zone.contains?("a.b.blog.example.com.")
    refute zone.contains?("example.com.")
    refute zone.contains?("xblog.example.com.")
  end

  def test_a_dot_inside_a_label_is_not_a_boundary
    # The single label "x.blog", then "example" and "com": a child of example.com., outside the zone.
    refute Dohyo::Zone.within?("x\\.blog.example.com.", ORIGIN)
    refute Dohyo::Zone.within?("a.x\\.blog.example.com.", ORIGIN)
    refute fixture_zone.contains?("x\\.blog.example.com.")
    # A label ending in a backslash ("x\"), then the zone's own labels: inside.
    assert Dohyo::Zone.within?("x\\\\.blog.example.com.", ORIGIN)
    assert Dohyo::Zone.within?("www.blog.example.com.", ORIGIN)
    assert Dohyo::Zone.within?(ORIGIN, ORIGIN)
  end

  def test_is_deeply_frozen
    assert Ractor.shareable?(fixture_zone)
  end

  def test_serial_newer_follows_rfc_1982
    assert Dohyo::Zone.serial_newer?(2026092302, 2026092301)
    refute Dohyo::Zone.serial_newer?(2026092301, 2026092302)
    refute Dohyo::Zone.serial_newer?(1, 1)
    assert Dohyo::Zone.serial_newer?(0, 2**32 - 1), "wraps around"
    assert Dohyo::Zone.serial_newer?(2**31 - 1, 0)
    refute Dohyo::Zone.serial_newer?(2**31, 0), "exactly 2^31 apart is undefined"
  end

  def test_equality_compares_content
    text = File.read(FIXTURE)
    same = Dohyo::Loader.parse(text.gsub(/^; .*\n/, "").gsub("IN A     ", "IN A "), origin: ORIGIN)
    changed = Dohyo::Loader.parse(text.sub("alpn=h3,h2", "alpn=h2"), origin: ORIGIN)

    assert_equal fixture_zone, same
    refute_equal fixture_zone, changed
  end
end
