# frozen_string_literal: true

require "test_helper"

class TestDohyo < Minitest::Test
  def test_that_it_has_a_version_number
    refute_nil ::Dohyo::VERSION
  end
end
