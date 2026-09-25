# frozen_string_literal: true

require "yaml"
require "ipaddr"

require_relative "errors"
require_relative "server"

module Dohyo
  # The configuration file: one YAML document, validated strictly. Unknown keys are errors, because a misspelled key
  # that is silently ignored is worse than refusing to start.
  Config = Data.define(:zone_origin, :zone_file, :listen, :tls, :udp_payload_size, :idle_timeout, :max_connections, :doq_max_streams, :metrics) do
    def self.load(path)
      # UTF-8 explicitly, whatever the locale; see Loader.load.
      text = begin
        File.read(path, encoding: Encoding::UTF_8)
      rescue SystemCallError => error
        raise ConfigError, "cannot read #{path}: #{error.message}"
      end
      raise ConfigError, "#{path} is not valid UTF-8" unless text.valid_encoding?

      parse(text)
    end

    def self.parse(text)
      Config::Parser.new(text).parse
    end

    # Whether any listener needs the TLS certificate.
    def tls_required?
      listen.any? { %w[tls quic].include?(it.scheme) }
    end
  end

  class Config
    DEFAULT_UDP_PAYLOAD_SIZE = 1232
    DEFAULT_IDLE_TIMEOUT = 10
    DEFAULT_MAX_CONNECTIONS = 256
    DEFAULT_DOQ_MAX_STREAMS = 16
    DEFAULT_METRICS_LISTEN = ["0.0.0.0:9153", "[::]:9153"].freeze

    UDP_PAYLOAD_SIZE_RANGE = (512..4096)

    TLS = Data.define(:certificate_chain, :private_key)

    # `host:port`, without a scheme. IPv6 hosts are written in brackets.
    MetricsListen = Data.define(:host, :port) do
      def loopback?
        IPAddr.new(host).loopback?
      rescue IPAddr::InvalidAddressError
        false
      end

      def to_s = "#{host.include?(":") ? "[#{host}]" : host}:#{port}"
    end

    Metrics = Data.define(:listen, :bearer_token_file) do
      # Anything other than loopback is reached over the internet, so it needs HTTPS and a bearer token.
      def exposed? = listen.any? { !it.loopback? }
    end

    # The allowed keys of each section. A nested Hash is a section; anything else is a leaf.
    SCHEMA = {
      "zone" => {"origin" => :leaf, "file" => :leaf},
      "listen" => :leaf,
      "tls" => {"certificate_chain" => :leaf, "private_key" => :leaf},
      "edns" => {"udp_payload_size" => :leaf},
      "connection" => {"idle_timeout" => :leaf, "max_connections" => :leaf},
      "doq" => {"max_streams_per_connection" => :leaf},
      "metrics" => {"listen" => :leaf, "bearer_token_file" => :leaf}
    }.freeze

    METRICS_LISTEN_PATTERN = /\A(?:\[(?<ipv6>[^\]]+)\]|(?<host>[^:\[\]\/]+)):(?<port>\d+)\z/

    class Parser
      def initialize(text)
        @text = text
      end

      def parse
        document = load_yaml
        check_keys(document, SCHEMA, [])

        listen = parse_listen(document)
        tls = parse_tls(document)
        metrics = parse_metrics(document)

        if listen.any? { %w[tls quic].include?(it.scheme) } && tls.nil?
          fail!("tls.certificate_chain and tls.private_key are required for tls:// and quic:// listeners")
        end

        if metrics&.exposed?
          fail!("metrics.bearer_token_file is required when metrics listens beyond loopback") unless metrics.bearer_token_file
          fail!("tls.certificate_chain and tls.private_key are required when metrics listens beyond loopback") unless tls
        end

        Config.new(
          zone_origin: parse_origin(document),
          zone_file: string(document, %w[zone file]),
          listen:,
          tls:,
          udp_payload_size: integer(document, %w[edns udp_payload_size], default: DEFAULT_UDP_PAYLOAD_SIZE, range: UDP_PAYLOAD_SIZE_RANGE),
          idle_timeout: integer(document, %w[connection idle_timeout], default: DEFAULT_IDLE_TIMEOUT, range: (1..)),
          max_connections: integer(document, %w[connection max_connections], default: DEFAULT_MAX_CONNECTIONS, range: (1..)),
          doq_max_streams: integer(document, %w[doq max_streams_per_connection], default: DEFAULT_DOQ_MAX_STREAMS, range: (1..)),
          metrics:
        )
      end

      private

      def fail!(message)
        raise ConfigError, message
      end

      # Only String, Integer, Array and Hash (plus the booleans and nil that YAML cannot avoid) are accepted; no
      # aliases, symbols, dates or objects. The value checks below reject anything else.
      def load_yaml
        document = YAML.safe_load(@text, permitted_classes: [], permitted_symbols: [], aliases: false)
        fail!("the configuration must be a mapping") unless document.is_a?(Hash)
        document
      rescue Psych::Exception => error
        fail!("cannot parse the configuration: #{error.message}")
      end

      def check_keys(hash, schema, path)
        hash.each do |key, value|
          location = [*path, key].join(".")
          fail!("unknown key #{location}") unless key.is_a?(String) && schema.key?(key)

          section = schema.fetch(key)
          next if section == :leaf

          fail!("#{location} must be a mapping") unless value.is_a?(Hash)
          check_keys(value, section, [*path, key])
        end
      end

      def fetch(document, path)
        path.reduce(document) { |hash, key| hash.is_a?(Hash) ? hash[key] : nil }
      end

      def string(document, path, required: true)
        value = fetch(document, path)
        return nil if value.nil? && !required
        fail!("#{path.join(".")} is required") if value.nil?
        fail!("#{path.join(".")} must be a string") unless value.is_a?(String) && !value.empty?

        value
      end

      def integer(document, path, default:, range:)
        value = fetch(document, path)
        return default if value.nil?
        fail!("#{path.join(".")} must be an integer") unless value.is_a?(Integer)
        fail!("#{path.join(".")} must be within #{range}") unless range.cover?(value)

        value
      end

      def parse_origin(document)
        origin = string(document, %w[zone origin])
        unless origin.end_with?(".") && origin.length > 1 && !origin.include?("..")
          fail!("zone.origin must be an absolute name with a trailing dot, not #{origin.inspect}")
        end

        origin.downcase(:ascii)
      end

      def parse_listen(document)
        entries = document["listen"]
        fail!("listen is required") if entries.nil?
        fail!("listen must be a list of scheme://host:port") unless entries.is_a?(Array) && !entries.empty? && entries.all?(String)

        listen = entries.map { Server::Listen.parse(it) }
        duplicate = listen.group_by(&:to_s).find { |_, group| group.size > 1 }
        fail!("listen has #{duplicate.first} more than once") if duplicate

        listen
      end

      def parse_tls(document)
        return nil unless document.key?("tls")

        TLS.new(certificate_chain: string(document, %w[tls certificate_chain]), private_key: string(document, %w[tls private_key]))
      end

      def parse_metrics(document)
        return nil unless document.key?("metrics")

        entries = fetch(document, %w[metrics listen]) || DEFAULT_METRICS_LISTEN
        fail!("metrics.listen must be a list of host:port") unless entries.is_a?(Array) && !entries.empty? && entries.all?(String)

        listen = entries.map { parse_metrics_listen(it) }
        duplicate = listen.group_by(&:to_s).find { |_, group| group.size > 1 }
        fail!("metrics.listen has #{duplicate.first} more than once") if duplicate

        Metrics.new(listen:, bearer_token_file: string(document, %w[metrics bearer_token_file], required: false))
      end

      def parse_metrics_listen(text)
        match = METRICS_LISTEN_PATTERN.match(text) or fail!("invalid metrics.listen address #{text.inspect}: expected host:port")
        port = Integer(match[:port], 10)
        fail!("port out of range in metrics.listen #{text.inspect}") unless (0..65535).cover?(port)

        MetricsListen.new(host: match[:ipv6] || match[:host], port:)
      end
    end
  end
end
