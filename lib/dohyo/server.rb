# frozen_string_literal: true

require "async"
require "io/endpoint"
require "io/endpoint/host_endpoint"
require "io/endpoint/wrapper"
require "console"

require_relative "version"
require_relative "errors"
require_relative "engine"
require_relative "handler"

module Dohyo
  # Binds the listeners and runs a handler for each. It never looks inside the responses.
  class Server
    LISTEN_SCHEMES = %w[udp tcp tls quic].freeze
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
    end

    # @parameter zone [Zone] The zone to answer from.
    # @parameter listen [Array<Listen>] Where to listen.
    # @parameter udp_payload_size [Integer] The EDNS(0) UDP payload size to advertise and the UDP response limit.
    def initialize(zone:, listen:, udp_payload_size:)
      @zone = zone
      @listen = listen
      @engine = Engine.new(zone_provider: -> { @zone }, udp_payload_size:)
      @wrapper = Wrapper.new
      @bound = []
      @tasks = []
    end

    attr_reader :zone, :engine

    # Replace the zone. Queries in progress keep the zone they started with.
    attr_writer :zone

    # @returns [Array(Array(String, Addrinfo))] The transport name and local address of each bound socket.
    def bound_addresses
      @bound.map { |transport, socket| [transport, socket.local_address] }
    end

    # Bind every listener and start answering in child tasks of `parent`. Returns once everything is bound.
    def start(parent = Async::Task.current)
      Console.info(self, "server.starting", version: VERSION, ruby: RUBY_VERSION, listen: @listen.map(&:to_s))

      @listen.each do |listen|
        endpoint = endpoint_for(listen)

        endpoint.bind.each do |socket|
          transport = listen.scheme
          @bound << [transport, socket]
          Console.info(self, "server.listening", transport:, address: socket.local_address.inspect_sockaddr)

          @tasks << parent.async(transient: true) { run_handler(transport, socket) }
        end
      end

      self
    end

    def stop
      @tasks.each(&:stop)
      @bound.each { |_, socket| socket.close unless socket.closed? }
      @tasks.clear
      @bound.clear
    end

    private

    def endpoint_for(listen)
      case listen.scheme
      when "udp" then IO::Endpoint.udp(listen.host, listen.port, wrapper: @wrapper)
      when "tcp" then IO::Endpoint.tcp(listen.host, listen.port, wrapper: @wrapper)
      end
    end

    def run_handler(transport, socket)
      case transport
      when "udp" then DatagramHandler.new(self, socket, engine: @engine, transport:).run(@wrapper)
      when "tcp" then StreamHandler.new(self, socket, engine: @engine, transport:).run(@wrapper)
      end
    end
  end
end
