# frozen_string_literal: true

require "test_helper"
require "tmpdir"

class TestReload < Minitest::Test
  include DohyoTestHelper

  def setup
    @directory = Dir.mktmpdir("dohyo-reload")
    @path = File.join(@directory, "blog.example.com.zone")
    write(serial: 1, address: "192.0.2.1")

    source = Dohyo::Loader::Source.new(origin: ORIGIN, path: @path)
    @server = Dohyo::Server.new(zone: source.load, zone_source: source, listen: [], udp_payload_size: 1232, max_connections: 1, idle_timeout: 1)
  end

  def teardown
    FileUtils.rm_rf(@directory)
  end

  def write(serial:, address:)
    File.write(@path, <<~ZONE)
      $ORIGIN blog.example.com.
      $TTL 3600
      @ IN SOA ns.example.com. hostmaster.example.com. ( #{serial} 7200 3600 1209600 300 )
      @ IN NS ns.example.com.
      @ IN A #{address}
    ZONE
  end

  def answer
    result = @server.engine.call(query_bytes("blog.example.com.", IN::A), transport: :udp)
    Resolv::DNS::Message.decode(result.bytes).answer.map { it[2].address.to_s }
  end

  def test_newer_serial_replaces_the_zone
    write(serial: 2, address: "192.0.2.2")
    assert_equal :replaced, @server.reload
    assert_equal 2, @server.zone.serial
    assert_equal ["192.0.2.2"], answer
  end

  def test_same_serial_and_content_is_unchanged
    zone = @server.zone
    assert_equal :unchanged, @server.reload
    assert_same zone, @server.zone
  end

  def test_same_serial_with_different_content_keeps_the_old_zone
    write(serial: 1, address: "192.0.2.2")
    assert_equal :failed, @server.reload
    assert_equal ["192.0.2.1"], answer
  end

  def test_older_serial_keeps_the_old_zone
    write(serial: 5, address: "192.0.2.5")
    @server.reload
    write(serial: 4, address: "192.0.2.4")
    assert_equal :failed, @server.reload
    assert_equal ["192.0.2.5"], answer
  end

  def test_broken_file_keeps_the_old_zone
    File.write(@path, "garbage\n")
    assert_equal :failed, @server.reload
    assert_equal ["192.0.2.1"], answer
  end
end
