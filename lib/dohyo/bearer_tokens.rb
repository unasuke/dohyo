# frozen_string_literal: true

require "openssl"

require_relative "errors"

module Dohyo
  # The tokens that may scrape /metrics: one per line in a file readable only by its owner. Two can be valid at once,
  # so that a token is replaced without a failed scrape.
  #
  # Tokens never appear in logs, metrics or error messages.
  class BearerTokens
    # @raises [ConfigError] If the file cannot be read, is readable by group or others, or has no token.
    def self.load(path)
      mode = File.stat(path).mode
      raise ConfigError, "#{path} must not be readable by group or others (it is #{format("%04o", mode & 0o7777)}; use 0600 or 0400)" unless (mode & 0o077).zero?

      # Tokens are compared as bytes, so read them as bytes, whatever the locale.
      tokens = File.readlines(path, chomp: true, encoding: Encoding::BINARY).map(&:strip).reject(&:empty?)
      raise ConfigError, "#{path} has no token" if tokens.empty?

      new(tokens)
    rescue SystemCallError => error
      raise ConfigError, "cannot read the metrics token file #{path}: #{error.class.name.split("::").last}"
    end

    def initialize(tokens)
      @tokens = tokens.map { it.b }.freeze
    end

    def count = @tokens.size

    # @parameter header [String, nil] The Authorization header.
    # @returns [Symbol] :ok, or why not: :missing, :malformed or :mismatch.
    def check(header)
      return :missing if header.nil? || header.empty?

      match = /\ABearer +(\S+)\s*\z/i.match(header) or return :malformed
      presented = match[1].b

      # Compare with every token, so that the time taken does not tell which one (or whether any) matched.
      matched = @tokens.map { OpenSSL.secure_compare(it, presented) }
      matched.any? ? :ok : :mismatch
    end

    # Never show the tokens, even in #inspect.
    def inspect = "#<#{self.class} count=#{count}>"
  end
end
