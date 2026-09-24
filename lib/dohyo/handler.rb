# frozen_string_literal: true

require "async"
require "async/dns"
require "console"
require "openssl"

module Dohyo
  # Logging shared by the handlers. The engine has no I/O, so the transports log on its behalf.
  module HandlerLogging
    private

    def log_result(result, transport, started_at)
      if result.error
        Console.error(self, "query.failed", transport:, error: result.error)
      end

      if result.dropped_reason
        Console.debug(self, "query.dropped", transport:, reason: result.dropped_reason)
      else
        Console.debug(self, "query.processed", transport:, qname: result.qname, qtype: result.qtype,
          rcode: result.rcode, tc: result.truncated, duration: Process.clock_gettime(Process::CLOCK_MONOTONIC) - started_at)
      end
    end
  end

  # Answers DNS over UDP.
  #
  # Overrides Async::DNS::DatagramHandler#respond (async-dns 1.4.1), which always sets AA, answers undecodable
  # queries with SERVFAIL and ID 0, and truncates anything over 512 bytes into a message with QR=0 and no question.
  # Here the engine does all of that according to RFC 1035 and RFC 6891.
  class DatagramHandler < Async::DNS::DatagramHandler
    include HandlerLogging

    def initialize(server, socket, engine:, transport: "udp")
      super(server, socket)
      @engine = engine
      @transport = transport
    end

    attr_reader :transport

    def respond(socket, input_data, remote_address)
      started_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      result = @engine.call(input_data, transport: :udp)
      log_result(result, @transport, started_at)

      socket.sendmsg(result.bytes, 0, remote_address) if result.bytes
    rescue IOError, SystemCallError => error
      Console.warn(self, "udp.send_failed", error:)
    end
  end

  # Answers DNS over TCP and DNS over TLS: 2-byte length-prefixed messages, one at a time per connection
  # (RFC 7766 §6.2.1.1 allows but does not require pipelined processing).
  #
  # Overrides Async::DNS::StreamHandler#handle_connection (async-dns 1.4.1), which answers through
  # Server#process_query (always AA=1, SERVFAIL with ID 0 on decode errors).
  class StreamHandler < Async::DNS::StreamHandler
    include HandlerLogging

    def initialize(server, socket, engine:, transport: "tcp")
      super(server, socket)
      @engine = engine
      @transport = transport
    end

    attr_reader :transport

    def handle_connection(socket)
      opened_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      queries = 0
      reason = "peer"

      while (length_data = socket.read(2)) && length_data.bytesize == 2
        length = length_data.unpack1("n")
        input_data = socket.read(length)
        break if input_data.nil? || input_data.bytesize < length

        queries += 1
        started_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        result = @engine.call(input_data, transport: :stream)
        log_result(result, @transport, started_at)

        # A query that is not answered (a response, or shorter than a header) ends the connection:
        unless result.bytes
          reason = "error"
          break
        end

        socket.write([result.bytes.bytesize].pack("n"), result.bytes)
        socket.flush
      end
    rescue IOError, SystemCallError, OpenSSL::SSL::SSLError => error
      reason = "error"
      Console.debug(self, "connection.error", transport: @transport, error:)
    ensure
      socket.close unless socket.closed?
      Console.debug(self, "connection.closed", transport: @transport, reason:, queries:,
        duration: Process.clock_gettime(Process::CLOCK_MONOTONIC) - opened_at)
    end
  end
end
