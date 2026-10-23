# frozen_string_literal: true

require "test_helper"
require "tmpdir"

class TestBearerTokens < Minitest::Test
  include DohyoTestHelper

  FIRST = "first-0123456789abcdef0123456789abcdef"
  SECOND = "second-0123456789abcdef0123456789abcdef"
  SECRET = "secret-0123456789abcdef0123456789abcdef"

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
    write("  #{FIRST}  \n\n#{SECOND}\n")
    tokens = Dohyo::BearerTokens.load(@path)
    assert_equal 2, tokens.count
    assert_equal :ok, tokens.check("Bearer #{FIRST}")
    assert_equal :ok, tokens.check("bearer #{SECOND}")
  end

  def test_check
    write("#{SECRET}\n")
    tokens = Dohyo::BearerTokens.load(@path)
    assert_equal :missing, tokens.check(nil)
    assert_equal :missing, tokens.check("")
    assert_equal :malformed, tokens.check("Basic c2VjcmV0")
    assert_equal :malformed, tokens.check("Bearer")
    assert_equal :mismatch, tokens.check("Bearer #{SECRET.chop}")
    assert_equal :mismatch, tokens.check("Bearer #{SECRET}s")
  end

  def test_owner_only_permissions
    write("#{SECRET}\n", mode: 0o400)
    assert_equal 1, Dohyo::BearerTokens.load(@path).count

    write("#{SECRET}\n", mode: 0o640)
    error = assert_raises(Dohyo::ConfigError) { Dohyo::BearerTokens.load(@path) }
    assert_match(/readable by group or others/, error.message)
  end

  def test_empty_file
    write("\n  \n")
    error = assert_raises(Dohyo::ConfigError) { Dohyo::BearerTokens.load(@path) }
    assert_match(/has no token/, error.message)
  end

  def test_short_token
    write("#{"a" * 32}\n")
    assert_equal 1, Dohyo::BearerTokens.load(@path).count

    write("#{SECRET}\n#{"b" * 31}\n")
    error = assert_raises(Dohyo::ConfigError) { Dohyo::BearerTokens.load(@path) }
    assert_match(/has a token shorter than 32 bytes \(use openssl rand -hex 32\)/, error.message)
    refute_includes error.message, "b" * 31
  end

  def test_missing_file
    error = assert_raises(Dohyo::ConfigError) { Dohyo::BearerTokens.load(File.join(@directory, "none")) }
    assert_match(/cannot read/, error.message)
  end

  def test_loads_under_the_c_locale_whatever_the_bytes
    File.binwrite(@path, "#{SECRET}\n#{"\xff\xfe" * 16}\n".b)
    File.chmod(0o600, @path)
    tokens = with_c_locale { Dohyo::BearerTokens.load(@path) }
    assert_equal :ok, tokens.check("Bearer #{SECRET}")
  end

  def test_tokens_never_show
    write("#{"hunter2" * 5}\n")
    tokens = Dohyo::BearerTokens.load(@path)
    refute_includes tokens.inspect, "hunter2"
  end
end
