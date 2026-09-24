# frozen_string_literal: true

require "test_helper"
require "json"
require "open3"
require "timeout"
require "tmpdir"

# Runs exe/dohyo as a child process and drives it with signals.
class TestProcess < Minitest::Test
  include DohyoTestHelper

  EXE = File.expand_path("../../exe/dohyo", __dir__)

  def setup
    @directory = Dir.mktmpdir("dohyo-process")
    @zone = File.join(@directory, "blog.example.com.zone")
    write_zone(serial: 1, address: "192.0.2.1")
    @config = File.join(@directory, "dohyo.yml")
    File.write(@config, <<~YAML)
      zone:
        origin: blog.example.com.
        file: #{@zone}
      listen:
        - udp://127.0.0.1:0
        - tcp://127.0.0.1:0
    YAML
  end

  def teardown
    if @pid
      Process.kill(:KILL, @pid)
      Process.wait(@pid)
    end
  rescue Errno::ESRCH, Errno::ECHILD
    nil
  ensure
    FileUtils.rm_rf(@directory)
  end

  def write_zone(serial:, address:)
    File.write(@zone, <<~ZONE)
      $ORIGIN blog.example.com.
      $TTL 3600
      @ IN SOA ns.example.com. hostmaster.example.com. ( #{serial} 7200 3600 1209600 300 )
      @ IN NS ns.example.com.
      @ IN A #{address}
    ZONE
  end

  # Starts the server and returns the UDP address it bound, read from its "server.listening" log.
  def start_server
    _stdin, @output, thread = Open3.popen2e({"CONSOLE_OUTPUT" => "Serialized"}, "ruby", EXE, "--config", @config)
    @pid = thread.pid
    @thread = thread

    Timeout.timeout(15) do
      @output.each_line do |line|
        event = begin
          JSON.parse(line)
        rescue
          next
        end
        next unless event["message"] == "server.listening" && event["transport"] == "udp"

        # Keep reading the log, so that the child never blocks on a full pipe:
        Thread.new {
          begin
            @output.each_line { nil }
          rescue
            IOError
          end
        }
        host, port = event["address"].split(":")
        return Addrinfo.udp(host, Integer(port))
      end
    end
    flunk "the server did not start"
  end

  def answer(address)
    socket = Socket.new(:INET, :DGRAM)
    socket.send(query_bytes("blog.example.com.", IN::A), 0, address.to_sockaddr)
    raise "no answer" unless socket.wait_readable(2)

    Resolv::DNS::Message.decode(socket.recv(65535)).answer.map { it[2].address.to_s }
  ensure
    socket&.close
  end

  def eventually(expected, seconds: 5)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + seconds
    loop do
      actual = yield
      return actual if actual == expected || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

      sleep 0.05
    end
  end

  def test_sighup_reloads_and_sigterm_exits_cleanly
    address = start_server
    assert_equal ["192.0.2.1"], answer(address)

    write_zone(serial: 2, address: "192.0.2.2")
    Process.kill(:HUP, @pid)
    assert_equal ["192.0.2.2"], eventually(["192.0.2.2"]) { answer(address) }

    # A broken zone keeps the previous one:
    File.write(@zone, "garbage\n")
    Process.kill(:HUP, @pid)
    sleep 0.2
    assert_equal ["192.0.2.2"], answer(address)

    Process.kill(:TERM, @pid)
    status = Timeout.timeout(10) { @thread.value }
    assert_predicate status, :success?
    @pid = nil
  end

  def test_sigint_exits_cleanly
    start_server
    Process.kill(:INT, @pid)
    assert_predicate Timeout.timeout(10) { @thread.value }, :success?
    @pid = nil
  end
end
