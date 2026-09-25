# frozen_string_literal: true

require "test_helper"
require "tmpdir"

class TestBearerTokens < Minitest::Test
  include DohyoTestHelper

  def setup
    @directory = Dir.mktmpdir("dohyo-tokens")
    @path = File.join(@directory, "tokens")
  end

  def teardown
    FileUtils.rm_rf(@directory)
  end

  def write(content, mode: 0o600)
    File.chmod(0o600, @path) if File.exist?(@path)
    File.write(@path, content)
    File.chmod(mode, @path)
  end

  def test_loads_one_token_per_line
    write("  first  \n\nsecond\n")
    tokens = Dohyo::BearerTokens.load(@path)
    assert_equal 2, tokens.count
    assert_equal :ok, tokens.check("Bearer first")
    assert_equal :ok, tokens.check("bearer second")
  end

  def test_check
    write("secret\n")
    tokens = Dohyo::BearerTokens.load(@path)
    assert_equal :missing, tokens.check(nil)
    assert_equal :missing, tokens.check("")
    assert_equal :malformed, tokens.check("Basic c2VjcmV0")
    assert_equal :malformed, tokens.check("Bearer")
    assert_equal :mismatch, tokens.check("Bearer secre")
    assert_equal :mismatch, tokens.check("Bearer secrets")
  end

  def test_owner_only_permissions
    write("secret\n", mode: 0o400)
    assert_equal 1, Dohyo::BearerTokens.load(@path).count

    write("secret\n", mode: 0o640)
    error = assert_raises(Dohyo::ConfigError) { Dohyo::BearerTokens.load(@path) }
    assert_match(/readable by group or others/, error.message)
  end

  def test_empty_file
    write("\n  \n")
    error = assert_raises(Dohyo::ConfigError) { Dohyo::BearerTokens.load(@path) }
    assert_match(/has no token/, error.message)
  end

  def test_missing_file
    error = assert_raises(Dohyo::ConfigError) { Dohyo::BearerTokens.load(File.join(@directory, "none")) }
    assert_match(/cannot read/, error.message)
  end

  def test_loads_under_the_c_locale_whatever_the_bytes
    File.binwrite(@path, "secret\n\xff\xfe\n".b)
    File.chmod(0o600, @path)
    tokens = with_c_locale { Dohyo::BearerTokens.load(@path) }
    assert_equal :ok, tokens.check("Bearer secret")
  end

  def test_tokens_never_show
    write("hunter2hunter2\n")
    tokens = Dohyo::BearerTokens.load(@path)
    refute_includes tokens.inspect, "hunter2"
  end
end
