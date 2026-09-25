# frozen_string_literal: true

require "async"
require "io/endpoint"
require "io/endpoint/host_endpoint"
require "io/endpoint/wrapper"
require "io/endpoint/ssl_endpoint"
require "console"

require_relative "version"
require_relative "errors"
require_relative "engine"
require_relative "loader"
require_relative "handler"
require_relative "tls"
require_relative "connection_limiter"
require_relative "metrics"

module Dohyo
  # Binds the listeners and runs a handler for each. It never looks inside the responses.
  class Server
    LISTEN_SCHEMES = %w[udp tcp tls quic].freeze

    # The transport name of each scheme, used in logs and metrics.
    TRANSPORTS = {"udp" => "udp", "tcp" => "tcp", "tls" => "dot", "quic" => "doq"}.freeze
    LISTEN_PATTERN = %r{\A(?<scheme>[a-z]+)://(?:\[(?<ipv6>[^\]]+)\]|(?<host>[^:\[\]/]+)):(?<port>\d+)\z}

    # One `scheme://host:port` entry of the listen list. IPv6 hosts are written in brackets.
    Listen = Data.define(:scheme, :host, :port) do
      def self.parse(text)
        match = LISTEN_PATTERN.match(text) or raise ConfigError, "invalid listen address #{text.inspect}: expected scheme://host:port"
        scheme = match[:scheme]
        raise ConfigError, "unsupported scheme #{scheme.inspect} in #{text.inspect}" unless LISTEN_SCHEMES.include?(scheme)

        port = Integer(match[:port], 10)
        raise ConfigError, "port out of range in #{text.inspect}" unless (0..65535).cover?(port)

        new(scheme:, host: match[:ipv6] || match[:host], port:)
      end

      def to_s = "#{scheme}://#{host.include?(":") ? "[#{host}]" : host}:#{port}"
    end

    # Binds IPv6 sockets with IPV6_V6ONLY, so that "[::]" never accepts IPv4-mapped addresses regardless of the
    # net.ipv6.bindv6only sysctl; IPv4 is listened on separately. Otherwise the same as IO::Endpoint::Wrapper#bind
    # (io-endpoint 0.18.0), which has no hook between creating and binding the socket.
    class Wrapper < IO::Endpoint::Wrapper
      def bind(local_address, protocol: 0, reuse_address: true, backlog: Socket::SOMAXCONN, **, &block)
        socket = nil

        begin
          socket = Socket.new(local_address.afamily, local_address.socktype, protocol)
          socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1) if reuse_address
          socket.ipv6only! if local_address.ipv6?
          socket.bind(local_address.to_sockaddr)
          socket.listen(backlog) if local_address.socktype == Socket::SOCK_STREAM
        rescue
          socket&.close
          raise
        end

        return socket unless block

        schedule do
          yield socket
        ensure
          socket.close
        end
      end

      # The same as IO::Endpoint::Wrapper#accept (io-endpoint 0.18.0), except:
      #
      # - A failed TLS handshake is an expected event (scanners, TLS 1.2 clients, clients giving up) rather than an
      #   unhandled exception in the connection's task, which Async would report as a warning with a backtrace.
      # - Connections beyond `limiter` are closed right after accept, before any TLS handshake.
      def accept(server, timeout: nil, limiter: nil, transport: nil, **, &block)
        loop do
          socket, address = begin
            socket_accept(server)
          rescue IOError, Errno::EBADF
            # The listening socket was closed to stop accepting (graceful shutdown).
            return if server.closed?

            raise
          end

          if limiter && !limiter.acquire
            socket.close
            Console.debug(self, "connection.closed", transport:, reason: "limit", queries: 0, duration: 0)
            next
          end

          set_timeout(socket, timeout) if timeout

          schedule do
            accept_connection(socket, address, &block)
          ensure
            limiter&.release
          end
        end
      end

      private

      def accept_connection(socket, address)
        if socket.respond_to?(:start)
          begin
            socket.start
          rescue OpenSSL::SSL::SSLError, IOError, SystemCallError => error
            Console.debug(self, "connection.handshake_failed", error:)
            socket.close
            return
          end
        end

        # OpenSSL does not return the peer address from accept:
        address ||= socket.remote_address

        yield socket, address
      end
    end

    # @parameter zone [Zone] The zone to answer from.
    # @parameter zone_source [Loader::Source, nil] Where #reload reads the zone again.
    # @parameter listen [Array<Listen>] Where to listen.
    # @parameter udp_payload_size [Integer] The EDNS(0) UDP payload size to advertise and the UDP response limit.
    # @parameter tls [TLS::Certificate, nil] The certificate for tls:// listeners.
    # @parameter max_connections [Integer] The limit shared by every stream listener.
    # @parameter idle_timeout [Numeric] Seconds a stream connection may stay silent (including the TLS handshake).
    # @parameter doq_max_streams [Integer] Concurrent streams a DoQ client may open per connection.
    # @parameter metrics [Metrics] Where the handlers count queries and connections.
    def initialize(zone:, listen:, udp_payload_size:, max_connections:, idle_timeout:, tls: nil, zone_source: nil, doq_max_streams: 16, metrics: Metrics.new)
      raise ConfigError, "tls:// and quic:// listeners need a certificate" if tls.nil? && listen.any? { %w[tls quic].include?(it.scheme) }

      @zone = zone
      @zone_source = zone_source
      @metrics = metrics
      @listen = listen
      @tls = tls
      @tls_context = TLS.server_context(tls) if tls
      @doq_max_streams = doq_max_streams
      @engine = Engine.new(zone_provider: -> { @zone }, udp_payload_size:)
      @wrapper = Wrapper.new
      @limiter = ConnectionLimiter.new(max_connections)
      @idle_timeout = idle_timeout
      @bound = []
      @waiting = Set.new
      @stopping = false
    end

    attr_reader :zone, :engine, :metrics

    # Replace the zone. Queries in progress keep the zone they started with.
    attr_writer :zone

    # Read the zone again and replace it, following the serial (RFC 1982):
    #
    # - newer: replace the zone;
    # - the same, with the same content: keep the zone (a SIGHUP without edits);
    # - the same with different content, older, or unreadable: keep the old zone and log why. A forgotten serial
    #   bump is caught here rather than served.
    #
    # @returns [Symbol] :replaced, :unchanged or :failed.
    def reload
      current = @zone
      zone = @zone_source.load

      if zone.serial == current.serial
        raise ZoneError.new("the serial #{zone.serial} is unchanged but the content changed", path: @zone_source.path) unless zone == current

        Console.info(self, "zone.reloaded", zone: zone.origin, serial: zone.serial, unchanged: true)
        return :unchanged
      end

      unless Zone.serial_newer?(zone.serial, current.serial)
        raise ZoneError.new("the serial #{zone.serial} is not newer than #{current.serial}", path: @zone_source.path)
      end

      @zone = zone
      Console.info(self, "zone.reloaded", zone: zone.origin, serial: zone.serial, unchanged: false)
      :replaced
    rescue ZoneError => error
      Console.error(self, "zone.load_failed", zone: current.origin, path: error.path, reason: error.message)
      :failed
    end

    # @returns [Array(Array(String, Addrinfo))] The transport name and local address of each bound socket.
    def bound_addresses
      @bound.map { |transport, socket, _| [transport, socket.local_address] }
    end

    # The open TCP, DoT and DoQ connections.
    def connection_count = @limiter.count

    # Whether a graceful shutdown has begun. Stream handlers close their connection after the answer in progress.
    def stopping? = @stopping

    # Stream handlers report whether a connection is between queries (waiting) or reading and answering one
    # (working), so that a shutdown can close the waiting ones at once and let the working ones finish.
    def connection_waiting(socket)
      @waiting << socket
    end

    def connection_working(socket)
      @waiting.delete(socket)
    end

    def connection_closed(socket)
      @waiting.delete(socket)
    end

    # Bind every listener and start answering in child tasks of `parent`. Returns once everything is bound.
    def start(parent = Async::Task.current)
      Console.info(self, "server.starting", version: VERSION, ruby: RUBY_VERSION, listen: @listen.map(&:to_s))

      @listen.each do |listen|
        next start_doq(parent, listen) if listen.scheme == "quic"

        endpoint = endpoint_for(listen)

        endpoint.bind.each do |socket|
          transport = TRANSPORTS.fetch(listen.scheme)
          task = parent.async(transient: true) { run_handler(transport, socket) }
          @bound << [transport, socket, task]
          Console.info(self, "server.listening", transport:, address: socket.local_address.inspect_sockaddr)
        end
      end

      self
    end

    # Stop at once, dropping every connection.
    def stop
      @bound.each do |_, socket, task|
        task.stop
        socket.close unless socket.closed?
      end
      @bound.clear
      @waiting.clear
    end

    GRACE_PERIOD = 5

    # Stop accepting, close the connections that are waiting between queries, and give the ones answering a query
    # up to `grace` seconds to finish before dropping them.
    def shutdown(grace: GRACE_PERIOD)
      started_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      @stopping = true

      @bound.each do |transport, socket, task|
        case transport
        # UDP has no connections: stopping its task is enough.
        when "udp" then task.stop
        # DoQ answers each query as soon as it arrives, so its connections can be closed with DOQ_NO_ERROR now.
        when "doq" then socket.shutdown
        # Closing a stream listener ends its accept loop while the connections it accepted keep running.
        else socket.close
        end
      end
      @waiting.to_a.each(&:close)

      deadline = started_at + grace
      sleep(0.01) while @limiter.count > 0 && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline

      stop
      Console.info(self, "server.stopped", duration: Process.clock_gettime(Process::CLOCK_MONOTONIC) - started_at)
    end

    private

    # protocol-quic is loaded only when a quic:// listener is configured, so that UDP, TCP and DoT work without it.
    def start_doq(parent, listen)
      require_relative "doq"

      listener = DoQ::Listener.new(host: listen.host, port: listen.port, engine: @engine, limiter: @limiter,
        idle_timeout: @idle_timeout, max_streams: @doq_max_streams, certificate: @tls, metrics: @metrics)
      task = parent.async(transient: true) { listener.run }
      @bound << ["doq", listener, task]
      Console.info(self, "server.listening", transport: "doq", address: listener.local_address.inspect_sockaddr)
    end

    def endpoint_for(listen)
      case listen.scheme
      when "udp" then IO::Endpoint.udp(listen.host, listen.port, wrapper: @wrapper)
      when "tcp" then IO::Endpoint.tcp(listen.host, listen.port, wrapper: @wrapper)
      # The TLS handshake runs in the connection's own fiber (SSLServer#start_immediately is false), so one slow
      # client cannot hold up the accept loop.
      when "tls" then IO::Endpoint::SSLEndpoint.new(IO::Endpoint.tcp(listen.host, listen.port, wrapper: @wrapper), ssl_context: @tls_context)
      end
    end

    def run_handler(transport, socket)
      case transport
      when "udp" then DatagramHandler.new(self, socket, engine: @engine, transport:).run(@wrapper)
      when "tcp", "dot" then StreamHandler.new(self, socket, engine: @engine, transport:).run(@wrapper, limiter: @limiter, transport:, timeout: @idle_timeout)
      end
    end
  end
end
