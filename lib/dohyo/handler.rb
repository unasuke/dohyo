# frozen_string_literal: true

require "async"
require "async/dns"
require "console"
require "openssl"

module Dohyo
  # Logs and metrics for each query, shared by every transport. The engine has no I/O, so the transports report on
  # its behalf.
  module QueryReport
    private

    def report_query(result, transport:, started_at:, metrics:)
      duration = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started_at
      Console.error(self, "query.failed", transport:, error: result.error) if result.error

      if result.dropped_reason
        Console.debug(self, "query.dropped", transport:, reason: result.dropped_reason)
        metrics.dropped(transport:, reason: result.dropped_reason)
      else
        Console.debug(self, "query.processed", transport:, qname: result.qname, qtype: result.qtype,
          rcode: result.rcode, tc: result.truncated, duration:)
        metrics.query(transport:, qtype: result.qtype, rcode: result.rcode, duration:, truncated: result.truncated)
      end
    end
  end

  # Answers DNS over UDP.
  #
  # Overrides Async::DNS::DatagramHandler#respond (async-dns 1.4.1), which always sets AA, answers undecodable
  # queries with SERVFAIL and ID 0, and truncates anything over 512 bytes into a message with QR=0 and no question.
  # Here the engine does all of that according to RFC 1035 and RFC 6891.
  class DatagramHandler < Async::DNS::DatagramHandler
    include QueryReport

    def initialize(server, socket, engine:, transport: "udp")
      super(server, socket)
      @engine = engine
      @transport = transport
    end

    attr_reader :transport

    def respond(socket, input_data, remote_address)
      started_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      result = @engine.call(input_data, transport: :udp)
      report_query(result, transport: @transport, started_at:, metrics: @server.metrics)

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
    include QueryReport

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

      loop do
        # Between queries the connection only waits; on shutdown the server closes such connections at once.
        @server.connection_waiting(socket)
        length_data = socket.read(2)
        @server.connection_working(socket)
        break unless length_data && length_data.bytesize == 2

        length = length_data.unpack1("n")
        input_data = socket.read(length)
        break if input_data.nil? || input_data.bytesize < length

        queries += 1
        started_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        result = @engine.call(input_data, transport: :stream)
        report_query(result, transport: @transport, started_at:, metrics: @server.metrics)

        # A query that is not answered (a response, or shorter than a header) ends the connection:
        unless result.bytes
          reason = "error"
          break
        end

        socket.write([result.bytes.bytesize].pack("n"), result.bytes)
        socket.flush

        # Answer the query in progress, then close (graceful shutdown):
        if @server.stopping?
          reason = "shutdown"
          break
        end
      end
    rescue IO::TimeoutError
      # The socket timeout (connection.idle_timeout) set by Server::Wrapper#accept: RFC 7766 §6.2.3.
      reason = "idle"
    rescue IOError, SystemCallError, OpenSSL::SSL::SSLError => error
      if @server.stopping?
        reason = "shutdown"
      else
        reason = "error"
        Console.debug(self, "connection.error", transport: @transport, error:)
      end
    ensure
      @server.connection_closed(socket)
      socket.close unless socket.closed?
      Console.debug(self, "connection.closed", transport: @transport, reason:, queries:,
        duration: Process.clock_gettime(Process::CLOCK_MONOTONIC) - opened_at)
    end
  end
end
