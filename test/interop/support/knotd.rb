# frozen_string_literal: true

require "socket"
require "tmpdir"
require "fileutils"
require "resolv"
require_relative "free_port"

# Runs knotd (Knot DNS) on a loopback port with one zone, for comparing its answers with dohyo's.
class Knotd
  READY_TIMEOUT = 5

  def self.installed?
    system("which knotd", out: File::NULL, err: File::NULL)
  end

  # Starts knotd, waits until it answers SOA for the zone, yields the Knotd and stops it.
  def self.run(origin:, path:, udp_payload_size:)
    knotd = new(origin:, path:, udp_payload_size:)
    knotd.start
    yield knotd
  ensure
    knotd&.stop
  end

  attr_reader :address

  def initialize(origin:, path:, udp_payload_size:)
    @origin = origin
    @path = File.expand_path(path)
    @udp_payload_size = udp_payload_size
  end

  def start
    @directory = Dir.mktmpdir("knotd")
    # If the port is taken before knotd binds it, knotd exits and wait_until_ready says so.
    @address = Addrinfo.udp("127.0.0.1", FreePort.pick)
    config = File.join(@directory, "knot.conf")
    File.write(config, configuration)
    @log = File.join(@directory, "knotd.log")
    @pid = Process.spawn("knotd", "-c", config, out: @log, err: [:child, :out])
    wait_until_ready
  end

  def stop
    if @pid
      Process.kill(:TERM, @pid)
      Process.wait(@pid)
    end
  rescue Errno::ESRCH, Errno::ECHILD
  ensure
    @pid = nil
    FileUtils.rm_rf(@directory) if @directory
  end

  private

  # The optional features Knot DNS turns on by default (the CHAOS identity and version, NSID) are off, as dohyo has none
  # of them. The zone file is only read, never written back.
  def configuration
    <<~CONF
      server:
          identity: ""
          version: ""
          nsid: ""
          rundir: "#{@directory}"
          listen: #{@address.ip_address}@#{@address.ip_port}
          udp-max-payload: #{@udp_payload_size}

      database:
          storage: "#{@directory}"

      log:
        - target: stderr
          any: warning

      template:
        - id: default
          storage: "#{@directory}"
          zonefile-sync: -1
          zonefile-load: whole
          journal-content: none

      zone:
        - domain: #{@origin}
          file: "#{@path}"
    CONF
  end

  def wait_until_ready
    query = Resolv::DNS::Message.new(1)
    query.add_question(@origin, Resolv::DNS::Resource::IN::SOA)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + READY_TIMEOUT

    loop do
      raise "knotd exited:\n#{File.read(@log)}" if Process.wait(@pid, Process::WNOHANG)

      socket = Socket.new(:INET, :DGRAM)
      begin
        socket.send(query.encode, 0, @address)
        if socket.wait_readable(0.1)
          response = Resolv::DNS::Message.decode(socket.recv(65535))
          return if response.rcode == Resolv::DNS::RCode::NoError && response.answer.any?
        end
      ensure
        socket.close
      end

      raise "knotd did not answer SOA within #{READY_TIMEOUT} seconds:\n#{File.read(@log)}" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      sleep 0.05
    end
  end
end
