# frozen_string_literal: true

module Dohyo
  # Counts the open TCP, DoT and DoQ connections against one shared limit (connection.max_connections).
  class ConnectionLimiter
    attr_reader :limit, :count

    def initialize(limit)
      @limit = limit
      @count = 0
    end

    # @returns [Boolean] false when the limit is reached; the caller must then close the connection.
    def acquire
      return false if @count >= @limit

      @count += 1
      true
    end

    def release
      @count -= 1 if @count > 0
    end
  end
end
