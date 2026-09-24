# frozen_string_literal: true

module Dohyo
  class Error < StandardError; end

  # The configuration file is unreadable, lacks a required key, has an unknown key, or has a malformed value.
  class ConfigError < Error; end

  # The zone file failed to parse or failed a load-time check.
  class ZoneError < Error
    attr_reader :path

    def initialize(message, path: nil)
      super(path ? "#{path}: #{message}" : message)
      @path = path
    end
  end

  # The resolution logic broke one of its own assumptions. Engine answers SERVFAIL.
  class ProtocolError < Error; end
end
