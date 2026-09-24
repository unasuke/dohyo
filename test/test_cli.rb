# frozen_string_literal: true

require "test_helper"
require "stringio"
require "tmpdir"
require "support/certificates"

class TestCLI < Minitest::Test
  include DohyoTestHelper

  def setup
    @directory = Dir.mktmpdir("dohyo-cli")
    @stdout = StringIO.new
    @stderr = StringIO.new
  end

  def teardown
    FileUtils.rm_rf(@directory)
  end

  def run_cli(*arguments)
    Dohyo::CLI.run(arguments, stdout: @stdout, stderr: @stderr)
  end

  def write_config(extra = "")
    path = File.join(@directory, "dohyo.yml")
    File.write(path, <<~YAML + extra)
      zone:
        origin: blog.example.com.
        file: #{FIXTURE}
      listen:
        - udp://127.0.0.1:0
    YAML
    path
  end

  def test_version
    assert_equal 0, run_cli("--version")
    assert_equal "#{Dohyo::VERSION}\n", @stdout.string
  end

  def test_help
    assert_equal 0, run_cli("--help")
    assert_match(/--config PATH/, @stdout.string)
  end

  def test_config_is_required
    assert_equal 2, run_cli
    assert_match(/missing argument: --config/, @stderr.string)
  end

  def test_unknown_option
    assert_equal 2, run_cli("--nope")
  end

  def test_check_prints_the_origin_and_serial
    assert_equal 0, run_cli("--config", write_config, "--check")
    assert_equal "blog.example.com. 2026092301\n", @stdout.string
  end

  def test_check_loads_the_certificate
    files = TestCertificates.write(File.join(@directory, "tls").tap { Dir.mkdir(it) })
    config = write_config(<<~YAML)
      tls:
        certificate_chain: #{files.certificate_chain}
        private_key: #{files.private_key}
    YAML
    assert_equal 0, run_cli("--config", config, "--check")

    File.write(files.private_key, TestCertificates.key.private_to_pem)
    assert_equal 1, run_cli("--config", config, "--check")
    assert_match(/does not match/, @stderr.string)
  end

  def test_invalid_configuration
    assert_equal 1, run_cli("--config", write_config("bogus: 1\n"), "--check")
    assert_match(/unknown key bogus/, @stderr.string)
  end

  def test_invalid_zone
    config = write_config.tap { File.write(it, File.read(it).sub(FIXTURE, "/nonexistent.zone")) }
    assert_equal 1, run_cli("--config", config, "--check")
    assert_match(/cannot read the zone file/, @stderr.string)
  end
end
