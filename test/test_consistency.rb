# frozen_string_literal: true

require "test_helper"

# The resolution logic must stay free of I/O, concurrency, logging and metrics, so that any transport can reuse it.
class TestConsistency < Minitest::Test
  PURE_FILES = %w[engine.rb edns.rb responder.rb zone.rb].map { File.expand_path("../lib/dohyo/#{it}", __dir__) }

  FORBIDDEN = %w[Async Socket IO::Endpoint Protocol::QUIC Console Thread File Metrics Signal trap YAML].freeze

  # Comments are dropped naively at the first "#". A "#" inside a string literal only removes more text, which
  # makes the check laxer, never stricter.
  def code_of(path)
    File.readlines(path, encoding: Encoding::UTF_8).map { it.sub(/#.*/, "") }.join
  end

  PURE_FILES.each do |path|
    define_method(:"test_#{File.basename(path, ".rb")}_has_no_io") do
      code = code_of(path)

      FORBIDDEN.each do |word|
        refute_match(/\b#{Regexp.escape(word)}\b/, code, "#{File.basename(path)} must not refer to #{word}")
      end
    end
  end
end
