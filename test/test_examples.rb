# frozen_string_literal: true

require "test_helper"

# The examples must stay valid as the code changes.
class TestExamples < Minitest::Test
  EXAMPLES = File.expand_path("../examples", __dir__)

  def test_configuration_example_is_valid
    config = Dohyo::Config.load(File.join(EXAMPLES, "dohyo.yml"))
    assert_equal "sub.example.com.", config.zone_origin
    assert config.metrics.exposed?
  end

  def test_zone_example_is_valid
    zone = Dohyo::Loader.load(origin: "sub.example.com.", path: File.join(EXAMPLES, "sub.example.com.zone"))
    assert_equal [1, 2, 6, 28, 65], zone.types_at("sub.example.com.")
  end
end
