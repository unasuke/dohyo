# frozen_string_literal: true

require "socket"
require "async"
require "console"

require_relative "errors"

begin
  require "protocol/quic"
rescue LoadError => error
  raise Dohyo::ConfigError, "DNS over QUIC needs the protocol-quic gem (the fork with the ruby-stream-io-bindings branch): #{error.message}"
end

module Dohyo
  # DNS over QUIC (RFC 9250) on top of protocol-quic.
  #
  # ngtcp2 calls back into Ruby while it processes a packet, and it must not be re-entered from there. The callbacks
  # therefore only buffer data and queue events; each connection has a fiber that checks the queries, asks the engine
  # and writes the answers, and another that runs the connection's timers (Protocol::QUIC::Server#run).
  module DoQ
    # RFC 9250 §4.3
    NO_ERROR = 0x0
    INTERNAL_ERROR = 0x1
    PROTOCOL_ERROR = 0x2
    REQUEST_CANCELLED = 0x3
    EXCESSIVE_LOAD = 0x4

    ALPN = "doq"

    # The 2-byte length prefix and the largest DNS message.
    MAX_STREAM_DATA = 2 + 65535

    # edns-tcp-keepalive (RFC 7828) must not be sent over DoQ (RFC 9250 §5.5.2).
    EDNS_TCP_KEEPALIVE = 11

    # One client-initiated bidirectional stream: one query, one response (RFC 9250 §4.2).
    class Stream < Protocol::QUIC::Stream
      def initialize(connection, stream_id)
        super
        @connection = connection
        @buffer = +"".b
        @finished = false
        @overflow = false
      end

      attr_reader :buffer

      # Called by ngtcp2 while it processes a packet: buffer only.
      def received(data, fin)
        return if @overflow || @finished

        @buffer << data

        if @buffer.bytesize > MAX_STREAM_DATA
          @overflow = true
          @connection.event(:protocol_error, "too_long")
        elsif fin
          @finished = true
          @connection.event(:query, self)
        end
      end

      # The client reset its side before sending FIN: abandon the query (RFC 9250 §4.3.1).
      def reset_received(_error_code)
        @connection.event(:cancelled, self) unless @finished
      end
    end

    # One QUIC connection.
    class Connection < Protocol::QUIC::Server
      attr_accessor :listener, :events, :opened_at, :queries, :close_reason, :counted

      def create_stream(stream_id) = Stream.new(self, stream_id)

      def event(*event)
        @events&.push(event)
      end

      def handshake_completed
        event(:handshake)
      end

      def disconnected
        @events&.close
        listener&.connection_gone(self)
      end
    end

    # Creates a Connection for every new QUIC connection the dispatcher sees.
    class Dispatcher < Protocol::QUIC::Dispatcher
      attr_accessor :listener

      def create_server(socket, address, packet_header)
        connection = Connection.new(self, configuration, tls_context, socket, address, packet_header, nil)
        listener.connection_created(connection)
        connection
      end
    end

    # Listens on one UDP address for DoQ.
    class Listener
      TRANSPORT = "doq"

      # @parameter certificate [TLS::Certificate] Its files are read again by protocol-quic.
      def initialize(host:, port:, engine:, limiter:, idle_timeout:, max_streams:, certificate:)
        @engine = engine
        @limiter = limiter
        @connections = Set.new
        @stopping = false

        family = host.include?(":") ? Socket::AF_INET6 : Socket::AF_INET
        address = Protocol::QUIC::Address.resolve(host, port.to_s, family, Socket::SOCK_DGRAM, Socket::AI_PASSIVE).first
        @socket = Protocol::QUIC::Socket.new(family, Socket::SOCK_DGRAM, Socket::IPPROTO_UDP)
        @socket.ipv6_only = true if family == Socket::AF_INET6
        raise ConfigError, "cannot bind quic://#{host}:#{port}" unless @socket.bind(address)

        @family = family
        @dispatcher = Dispatcher.new(configuration(idle_timeout:, max_streams:), tls_context(certificate))
        @dispatcher.listener = self
      end

      def local_address
        Addrinfo.new(@socket.local_address.data, @family, Socket::SOCK_DGRAM)
      end

      def closed? = @socket.nil?

      # Receives packets until stopped. Runs in its own task.
      def run(task = Async::Task.current)
        @task = task
        loop { @dispatcher.listen(@socket) }
      end

      # Answer what is already queued, then close every connection with DOQ_NO_ERROR (RFC 9250 §4.3) and stop.
      def shutdown
        @stopping = true
        @connections.to_a.each { close_connection(it, NO_ERROR, "shutdown") }
        @connections.clear
      end

      def close
        @socket&.close
        @socket = nil
      end

      def connection_created(connection)
        connection.listener = self
        connection.events = Thread::Queue.new
        connection.opened_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        connection.queries = 0
        @connections << connection

        # Both start at once and wait almost immediately, so they return here before the packet is processed.
        @task.async(transient: true) { serve(connection) }
        @task.async(transient: true) { connection.run }
      end

      def connection_gone(connection)
        @connections.delete(connection)
        @limiter.release if connection.counted
        connection.counted = false

        Console.debug(self, "connection.closed", transport: TRANSPORT, reason: connection.close_reason || "peer",
          queries: connection.queries, duration: Process.clock_gettime(Process::CLOCK_MONOTONIC) - connection.opened_at)
      end

      private

      def configuration(idle_timeout:, max_streams:)
        configuration = Protocol::QUIC::Configuration.new
        configuration.max_idle_timeout = idle_timeout
        configuration.initial_max_streams_bidi = max_streams
        # Clients may not open unidirectional streams (RFC 9250 §4.3.3); a limit of 0 makes ngtcp2 refuse them.
        configuration.initial_max_streams_uni = 0
        configuration
      end

      def tls_context(certificate)
        context = Protocol::QUIC::TLS::ServerContext.new
        context.add_protocol(ALPN)
        context.load_certificate_file(certificate.chain_path)
        context.load_private_key_file(certificate.key_path)
        context
      end

      def serve(connection)
        while (event = connection.events.pop)
          kind, argument = event

          case kind
          when :handshake then admit(connection)
          when :query then answer(connection, argument)
          when :cancelled then argument.abort(REQUEST_CANCELLED)
          when :protocol_error then protocol_error(connection, argument)
          end

          connection.send_packets unless connection.disconnected?
        end
      end

      # The connection limit is shared with TCP and DoT. The connection is closed after the handshake, with a reason
      # the client can see, rather than dropped silently.
      def admit(connection)
        if @stopping
          close_connection(connection, NO_ERROR, "shutdown")
        elsif @limiter.acquire
          connection.counted = true
        else
          close_connection(connection, EXCESSIVE_LOAD, "limit")
        end
      end

      def answer(connection, stream)
        data = stream.buffer
        length = data.unpack1("n") if data.bytesize >= 2
        # The 2-byte length must match what arrived before FIN: nothing missing, no second query (RFC 9250 §4.2).
        return protocol_error(connection, "length_mismatch") unless length && data.bytesize == 2 + length

        message = data.byteslice(2, length)
        # RFC 9250 §4.2.1: the Message ID must be 0.
        return protocol_error(connection, "nonzero_id") unless message.bytesize >= 2 && message.unpack1("n").zero?

        started_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        result = @engine.call(message, transport: :stream)
        log_result(result, started_at)

        return protocol_error(connection, "keepalive_option") if result.edns_option_codes.include?(EDNS_TCP_KEEPALIVE)
        return protocol_error(connection, "malformed") unless result.bytes

        connection.queries += 1
        begin
          stream.write([result.bytes.bytesize].pack("n") + result.bytes)
          stream.finish
        rescue => error
          # RFC 9250 §4.3.2: an answer that cannot be sent resets the stream.
          Console.error(self, "query.failed", transport: TRANSPORT, error:)
          stream.abort(INTERNAL_ERROR)
        end
      end

      def protocol_error(connection, reason)
        Console.info(self, "doq.protocol_error", reason:)
        close_connection(connection, PROTOCOL_ERROR, "protocol_error")
      end

      def close_connection(connection, code, reason)
        return if connection.disconnected?

        connection.close_reason ||= reason
        connection.close(code)
      end

      def log_result(result, started_at)
        Console.error(self, "query.failed", transport: TRANSPORT, error: result.error) if result.error
        Console.debug(self, "query.processed", transport: TRANSPORT, qname: result.qname, qtype: result.qtype,
          rcode: result.rcode, tc: result.truncated, duration: Process.clock_gettime(Process::CLOCK_MONOTONIC) - started_at)
      end
    end
  end
end
