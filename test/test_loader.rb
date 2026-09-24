# frozen_string_literal: true

require "test_helper"
require "tmpdir"

class TestLoader < Minitest::Test
  include DohyoTestHelper

  HEADER = <<~ZONE
    $ORIGIN blog.example.com.
    $TTL 3600
    @ IN SOA ns.example.com. hostmaster.example.com. ( 1 7200 3600 1209600 300 )
    @ IN NS ns.example.com.
  ZONE

  def parse(body, header: HEADER)
    Dohyo::Loader.parse(header + body, origin: ORIGIN, path: "test.zone")
  end

  def assert_zone_error(pattern, body = "", header: HEADER)
    error = assert_raises(Dohyo::ZoneError) { parse(body, header:) }
    assert_match pattern, error.message
    assert_equal "test.zone", error.path
    error
  end

  def https_params(value)
    zone = parse("@ IN HTTPS 1 . #{value}\n")
    _, records = zone.rrset(ORIGIN, 65)
    records.first.params.to_a
  end

  def test_loads_the_fixture
    zone = Dohyo::Loader.load(origin: ORIGIN, path: FIXTURE)
    assert_equal 2026092301, zone.serial
  end

  def test_unreadable_file
    error = assert_raises(Dohyo::ZoneError) { Dohyo::Loader.load(origin: ORIGIN, path: "/nonexistent/zone") }
    assert_match(/cannot read/, error.message)
  end

  def test_parse_error
    assert_zone_error(/cannot parse/, "@ IN A\n")
  end

  def test_origin_is_required
    assert_zone_error(/\$ORIGIN is missing/, "", header: HEADER.sub("$ORIGIN blog.example.com.\n", ""))
  end

  def test_origin_must_match_the_configuration
    assert_zone_error(/does not match the configured origin/, "", header: HEADER.sub("$ORIGIN blog.example.com.", "$ORIGIN example.com."))
  end

  def test_origin_is_compared_case_insensitively
    zone = parse("", header: HEADER.sub("$ORIGIN blog.example.com.", "$ORIGIN BLOG.Example.COM."))
    assert_equal ORIGIN, zone.origin
  end

  def test_ttl_directive_with_a_unit_is_rejected
    assert_zone_error(/\$TTL must be a number of seconds/, "", header: HEADER.sub("$TTL 3600", "$TTL 1h"))
  end

  def test_record_ttl_with_a_unit_is_accepted
    zone = parse("www 1h IN A 192.0.2.1\n")
    assert_equal 3600, zone.rrset("www.blog.example.com.", 1).first
  end

  def test_unsupported_type
    assert_zone_error(/unsupported record type TXT/, %(@ IN TXT "hello"\n))
  end

  def test_exactly_one_soa
    # dns-zonefile drops every SOA after the first; the loader counts them itself.
    assert_zone_error(/exactly one SOA, found 2/, "@ IN SOA ns2.example.com. hostmaster.example.com. ( 2 7200 3600 1209600 300 )\n")
  end

  def test_ns_at_the_apex_is_required
    assert_zone_error(/at least one NS/, "", header: HEADER.sub("@ IN NS ns.example.com.\n", ""))
  end

  def test_ns_below_the_apex_is_rejected
    assert_zone_error(/NS is only allowed at the apex/, "sub IN NS ns.example.net.\n")
  end

  def test_soa_below_the_apex_is_rejected
    header = HEADER.sub("@ IN SOA", "sub IN SOA")
    assert_zone_error(/SOA is only allowed at the apex/, "", header:)
  end

  def test_names_outside_the_zone_are_rejected
    assert_zone_error(/outside the zone/, "www.example.org. IN A 192.0.2.1\n")
  end

  def test_wildcards_are_rejected
    assert_zone_error(/wildcards are not supported/, "* IN A 192.0.2.1\n")
  end

  def test_ttl_out_of_range
    assert_zone_error(/out of range/, "www 2147483648 IN A 192.0.2.1\n")
  end

  def test_ttl_at_the_limit_is_accepted
    assert_equal 2147483647, parse("www 2147483647 IN A 192.0.2.1\n").rrset("www.blog.example.com.", 1).first
  end

  def test_addresses_are_validated
    assert_zone_error(/not an IPv4 address/, "www IN A 256.0.2.1\n")
    assert_zone_error(/not an IPv6 address/, "www IN AAAA 192.0.2.1\n")
  end

  def test_ttl_mismatch_within_an_rrset_uses_the_smallest
    zone = parse("www 300 IN A 192.0.2.1\nwww 600 IN A 192.0.2.2\n")
    ttl, records = zone.rrset("www.blog.example.com.", 1)
    assert_equal 300, ttl
    assert_equal 2, records.size
  end

  def test_identical_records_are_merged
    zone = parse("www IN A 192.0.2.1\nwww IN A 192.0.2.1\n")
    assert_equal 1, zone.rrset("www.blog.example.com.", 1).last.size
  end

  def test_https_alias_mode_and_multiple_records
    zone = parse("@ IN HTTPS 0 cdn.example.net.\n@ IN HTTPS 2 . alpn=h2\n")
    _, records = zone.rrset(ORIGIN, 65)
    assert_equal [0, 2], records.map(&:priority).sort
  end

  def test_https_every_known_key
    params = https_params('mandatory=alpn,key3 alpn=h3,h2 no-default-alpn port=8443 ipv4hint=192.0.2.1,192.0.2.2 ech=AEX+DQ== ipv6hint=2001:db8::1 dohpath="/q{?dns}" key65000=opaque')
    by_class = params.to_h { [it.class, it] }

    assert_equal [1, 3], by_class.fetch(Resolv::DNS::SvcParam::Mandatory).keys
    assert_equal %w[h3 h2], by_class.fetch(Resolv::DNS::SvcParam::ALPN).protocol_ids
    assert by_class.key?(Resolv::DNS::SvcParam::NoDefaultALPN)
    assert_equal 8443, by_class.fetch(Resolv::DNS::SvcParam::Port).port
    assert_equal %w[192.0.2.1 192.0.2.2], by_class.fetch(Resolv::DNS::SvcParam::IPv4Hint).addresses.map(&:to_s)
    assert_equal %w[2001:db8::1], by_class.fetch(Resolv::DNS::SvcParam::IPv6Hint).addresses.map(&:to_s)
    assert_equal "/q{?dns}", by_class.fetch(Resolv::DNS::SvcParam::DoHPath).template

    generic = params.select { it.is_a?(Resolv::DNS::SvcParam::Generic) }.to_h { [it.class::KeyNumber, it.value] }
    assert_equal({5 => "AEX+DQ==".unpack1("m0"), 65000 => "opaque"}, generic)
  end

  def test_https_key_number_uses_the_known_format
    params = https_params("key3=443")
    assert_equal 443, params.first.port
  end

  def test_https_encodes_keys_in_ascending_order
    zone = parse("@ IN HTTPS 1 . port=443 alpn=h2\n")
    rdata = Dohyo::Zone.rdata(zone.rrset(ORIGIN, 65).last.first)
    # priority (2) + target "." (1), then key 1 (alpn) before key 3 (port):
    assert_equal [1, 3], [rdata.byteslice(3, 2).unpack1("n"), rdata.byteslice(3 + 4 + 3, 2).unpack1("n")]
  end

  def test_https_invalid_values
    assert_zone_error(/port must be/, "@ IN HTTPS 1 . port=abc\n")
    assert_zone_error(/port must be/, "@ IN HTTPS 1 . port=65536\n")
    assert_zone_error(/not an IPv4 address/, "@ IN HTTPS 1 . ipv4hint=2001:db8::1\n")
    assert_zone_error(/invalid value/, "@ IN HTTPS 1 . ech=!!!\n")
    assert_zone_error(/no-default-alpn takes no value/, "@ IN HTTPS 1 . no-default-alpn=x\n")
    assert_zone_error(/empty value/, "@ IN HTTPS 1 . alpn=h2,,h3\n")
  end

  def test_https_unknown_key
    assert_zone_error(/unknown SvcParamKey foo/, "@ IN HTTPS 1 . foo=1\n")
  end

  def test_https_key_number_out_of_range
    assert_zone_error(/out of range/, "@ IN HTTPS 1 . key65536=x\n")
  end

  def test_https_escapes_are_rejected
    assert_zone_error(/escapes/, "@ IN HTTPS 1 . alpn=h2\\,h3\n")
  end

  def test_https_duplicate_key_numbers_are_rejected
    assert_zone_error(/appears more than once/, "@ IN HTTPS 1 . dohpath=/a key7=/b\n")
  end

  def test_load_reads_a_file
    Dir.mktmpdir do |dir|
      path = File.join(dir, "blog.example.com.zone")
      File.write(path, HEADER)
      assert_equal 1, Dohyo::Loader.load(origin: ORIGIN, path:).serial
    end
  end
end
