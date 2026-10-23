# frozen_string_literal: true

require "async"
require "async/http/server"
require "async/http/protocol/http1"
require "protocol/http/response"
require "protocol/http/headers"
require "protocol/http1/error"
require "io/stream"
require "io/endpoint/host_endpoint"
require "io/endpoint/ssl_endpoint"
require "console"

require_relative "metrics"
require_relative "tls"
require_relative "server"
require_relative "connection_limiter"

module Dohyo
  # Serves GET /metrics for Prometheus.
  #
  # On loopback only, it is plain HTTP without authentication. Anywhere else it is reached over the internet, so it
  # is HTTPS (the DoT certificate) and every request needs a bearer token; Config enforces that both are set.
  class MetricsServer
    PATH = "/metrics"

    # Scrapers keep connections open between scrapes; drop them after this long without a request.
    IDLE_TIMEOUT = 60

    # The most a TLS handshake may take in all. IDLE_TIMEOUT applies to each read and cannot cut a slow ClientHello.
    HANDSHAKE_TIMEOUT = 10

    # Open connections across every listen address. Prometheus needs one or two; the limit is there so that
    # unauthenticated clients cannot use up the descriptors the DNS listeners share.
    MAX_CONNECTIONS = 16

    # Header fields in a request, and their total size (without the line endings). Every request is read in full
    # before its token is checked, so these bound what an unauthenticated client can make the server hold.
    MAX_HEADER_FIELDS = 64
    MAX_HEADER_BYTES = 16 * 1024

    # The most the request line and the headers may take to arrive, once the first byte of a request has.
    REQUEST_TIMEOUT = 10

    # An HTTP/1 server connection with limits on what it reads before the request reaches #respond.
    class Connection < Async::HTTP::Protocol::HTTP1::Server
      def initialize(stream, version, request_timeout:, **options)
        super(stream, version, **options)
        @request_timeout = request_timeout
      end

      # Waiting for the next request on a kept-alive connection is bounded only by IDLE_TIMEOUT, which applies to
      # each read. Once a request has begun, its line and headers must arrive within the request timeout in all,
      # however slowly they trickle in. On EOF, the original returns nil as before.
      def read_request(&block)
        return super if @stream.peek(1).empty?

        Async::Task.current.with_timeout(@request_timeout) { super(&block) }
      end

      # The same as protocol-http1 0.41.0, which reads header lines without any limit, except for the two limits.
      # Protocol::HTTP1::BadHeader makes async-http answer 400 and close the connection.
      def read_headers
        fields = []
        size = 0

        while (line = read_line)
          break if line.empty?

          size += line.bytesize
          raise ::Protocol::HTTP1::BadHeader, "more than #{MAX_HEADER_FIELDS} header fields" if fields.size >= MAX_HEADER_FIELDS
          raise ::Protocol::HTTP1::BadHeader, "header fields over #{MAX_HEADER_BYTES} bytes" if size > MAX_HEADER_BYTES

          match = ::Protocol::HTTP1::HEADER.match(line) or raise ::Protocol::HTTP1::BadHeader, "Could not parse header: #{line.inspect}"
          fields << [match[1], match[2] || ""]
        end

        ::Protocol::HTTP::Headers.new(fields)
      end
    end

    # Passed to Async::HTTP::Server as its protocol: wraps each accepted connection in a Connection. Not named
    # Protocol, which would hide the ::Protocol of protocol-http inside this class.
    HTTPProtocol = Data.define(:request_timeout) do
      def server(peer) = Connection.new(::IO::Stream(peer), Async::HTTP::Protocol::HTTP1::VERSION, request_timeout:)
    end

    # @parameter listen [Array<Config::MetricsListen>]
    # @parameter tls [TLS::Certificate, nil] HTTPS when given.
    # @parameter tokens [BearerTokens, nil] Required when given.
    # @parameter max_connections [Integer] For tests, like the timeouts below; the configuration cannot change it.
    # @parameter handshake_timeout [Numeric]
    # @parameter request_timeout [Numeric]
    def initialize(listen:, metrics:, tls: nil, tokens: nil, max_connections: MAX_CONNECTIONS, handshake_timeout: HANDSHAKE_TIMEOUT, request_timeout: REQUEST_TIMEOUT)
      @listen = listen
      @metrics = metrics
      @limiter = ConnectionLimiter.new(max_connections)
      @handshake_timeout = handshake_timeout
      @tls_context = TLS.server_context(tls, alpn: ["http/1.1"]) if tls
      @tokens = tokens
      @wrapper = Server::Wrapper.new
      @http = Async::HTTP::Server.new(method(:respond), nil, protocol: HTTPProtocol.new(request_timeout:), scheme: tls ? "https" : "http")
      @bound = []
    end

    # Replaced on SIGHUP. Requests in progress keep the tokens they started with.
    attr_writer :tokens

    def bound_addresses = @bound.map { |socket, _| socket.local_address }

    def start(parent = Async::Task.current)
      @listen.each do |listen|
        endpoint = IO::Endpoint.tcp(listen.host, listen.port, wrapper: @wrapper)
        endpoint = IO::Endpoint::SSLEndpoint.new(endpoint, ssl_context: @tls_context) if @tls_context

        endpoint.bind.each do |socket|
          task = parent.async(transient: true) do
            @wrapper.accept(socket, timeout: IDLE_TIMEOUT, handshake_timeout: @handshake_timeout, limiter: @limiter, transport: "metrics") { |peer, address| @http.accept(peer, address) }
          end
          @bound << [socket, task]
          Console.info(self, "server.listening", transport: "metrics", address: socket.local_address.inspect_sockaddr, tls: !@tls_context.nil?)
        end
      end

      self
    end

    def stop
      @bound.each do |socket, task|
        task.stop
        socket.close unless socket.closed?
      end
      @bound.clear
    end

    private

    # Authentication comes first: without a valid token, every request gets 401 and learns nothing else.
    def respond(request)
      if @tokens && (result = @tokens.check(request.headers["authorization"]&.to_s)) != :ok
        # The token itself is never logged, not even in part.
        Console.warn(self, "metrics.auth_failed", reason: result)
        return response(401, "unauthorized\n", "www-authenticate" => "Bearer")
      end

      return response(404, "not found\n") unless request.path.split("?", 2).first == PATH
      return response(405, "method not allowed\n", "allow" => "GET") unless request.method == "GET"

      response(200, @metrics.render, "content-type" => Metrics::CONTENT_TYPE)
    end

    def response(status, body, headers = {})
      Protocol::HTTP::Response[status, {"content-type" => "text/plain; charset=utf-8"}.merge(headers), [body]]
    end
  end
end
