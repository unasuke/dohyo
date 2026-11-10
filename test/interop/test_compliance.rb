# frozen_string_literal: true

require "test_helper"
require "async"
require "open3"
require "yaml"
require_relative "support/free_port"

# Runs ISC's genreport (DNS-Compliance-Testing, built from test/interop/genreport/Dockerfile) against dohyo with the
# EDNS, full and common tests. Every test not in genreport_allowlist.yml must report ok.
class TestInteropCompliance < Minitest::Test
  include DohyoTestHelper

  IMAGE = "dohyo-genreport"
  DOCKERFILE_DIRECTORY = File.expand_path("genreport", __dir__)
  ALLOWLIST = File.expand_path("genreport_allowlist.yml", __dir__)
  ZONE = "blog.example.com"

  def setup
    skip "docker is not installed" unless system("which docker", out: File::NULL, err: File::NULL)

    output, status = Open3.capture2e("docker", "build", "-q", "-t", IMAGE, DOCKERFILE_DIRECTORY)
    flunk "docker build failed:\n#{output}" unless status.success?
  end

  def test_every_test_not_allowed_to_fail_is_ok
    allowlist = load_allowlist
    results = parse(genreport)

    refute_empty results, "genreport reported no tests"
    failed = results.reject { |_, values| values.include?("ok") }
    assert_empty failed.except(*allowlist).map { |name, values| "#{name}=#{values.join(",")}" }, "tests that are not ok"
    assert_empty allowlist.reject { failed.key?(it) }, "allowed failures that no longer fail"
  end

  private

  # The names of the tests allowed to fail. Each entry needs a reason and the RFC behind it.
  def load_allowlist
    YAML.safe_load_file(ALLOWLIST).map do |entry|
      id, reason, rfc = entry.values_at("id", "reason", "rfc")
      raise "#{ALLOWLIST}: #{id}: a reason and an RFC are required" if reason.to_s.empty? || rfc.to_s.empty?

      id
    end
  end

  # genreport takes "zone server address" on stdin and queries the address on one port for both UDP and TCP.
  def genreport
    port = FreePort.pick
    listen = %W[udp://127.0.0.1:#{port} tcp://127.0.0.1:#{port}].map { Dohyo::Server::Listen.parse(it) }

    Sync do |task|
      server = Dohyo::Server.new(zone: fixture_zone, listen:, udp_payload_size: 1232, max_connections: 16, idle_timeout: 10)
      server.start(task)
      command = ["docker", "run", "--rm", "-i", "--network", "host", IMAGE, "-f", "-c", "-P", port.to_s]
      # docker blocks, so it runs in a thread while the reactor keeps serving.
      output, errors, status = Thread.new { Open3.capture3(*command, stdin_data: "#{ZONE} ns.example.com 127.0.0.1\n") }.value
      flunk "genreport failed:\n#{errors}" unless status.success?
      output
    ensure
      server&.stop
    end
  end

  # "blog.example.com. @127.0.0.1 (ns.example.com.): dns=ok tc=formerr edns@512=ok,notc ..." to test name => tags.
  def parse(output)
    line = output.lines.find { it.start_with?("#{ZONE}. @127.0.0.1 ") }
    flunk "no report for #{ZONE} in:\n#{output}" unless line

    line.split(": ", 2).last.split.to_h do |item|
      name, tags = item.split("=", 2)
      [name, tags.to_s.split(",")]
    end
  end
end
