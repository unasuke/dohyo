# frozen_string_literal: true

require "optparse"
require "async"
require "console"

require_relative "version"
require_relative "errors"
require_relative "config"
require_relative "loader"
require_relative "tls"
require_relative "server"

module Dohyo
  # `dohyo --config PATH [--check]`.
  #
  # Exit status: 0 on success, 1 when the configuration, the zone or the certificate is invalid, 2 for bad
  # arguments.
  class CLI
    EXIT_OK = 0
    EXIT_INVALID = 1
    EXIT_USAGE = 2

    SIGNALS = {"HUP" => "H", "TERM" => "T", "INT" => "I"}.freeze

    def self.run(arguments = ARGV, stdout: $stdout, stderr: $stderr)
      new(stdout:, stderr:).run(arguments)
    end

    def initialize(stdout:, stderr:)
      @stdout = stdout
      @stderr = stderr
    end

    def run(arguments)
      options = parse(arguments)
      return options if options.is_a?(Integer)

      config = Config.load(options.fetch(:config))
      zone_source = Loader::Source.new(origin: config.zone_origin, path: config.zone_file)
      zone = zone_source.load
      tls = TLS.load(certificate_chain: config.tls.certificate_chain, private_key: config.tls.private_key) if config.tls

      if options[:check]
        @stdout.puts "#{zone.origin} #{zone.serial}"
        return EXIT_OK
      end

      Console.info(self, "zone.loaded", zone: zone.origin, path: zone_source.path, serial: zone.serial, records: zone.record_count)
      serve(config, zone, zone_source, tls)
      EXIT_OK
    rescue ConfigError, ZoneError => error
      @stderr.puts "dohyo: #{error.message}"
      EXIT_INVALID
    end

    private

    def parse(arguments)
      options = {}
      parser = OptionParser.new do |opts|
        opts.banner = "Usage: dohyo --config PATH [--check]"
        opts.on("--config PATH", "The configuration file (required)") { options[:config] = it }
        opts.on("--check", "Check the configuration, the zone and the certificate, then exit") { options[:check] = true }
        opts.on("--version", "Print the version and exit") do
          @stdout.puts VERSION
          return EXIT_OK
        end
        opts.on("-h", "--help", "Print this help and exit") do
          @stdout.puts opts
          return EXIT_OK
        end
      end

      rest = parser.parse(arguments)
      raise OptionParser::InvalidArgument, rest.join(" ") unless rest.empty?
      raise OptionParser::MissingArgument, "--config" unless options[:config]

      options
    rescue OptionParser::ParseError => error
      @stderr.puts "dohyo: #{error.message}"
      @stderr.puts parser
      EXIT_USAGE
    end

    def serve(config, zone, zone_source, tls)
      # Signals arrive through a self-pipe: the trap handler only writes a byte, and a task does the work, so no
      # lock is ever taken inside a trap.
      reader, writer = IO.pipe
      previous = SIGNALS.to_h do |signal, byte|
        [signal, Signal.trap(signal) { writer.write_nonblock(byte, exception: false) }]
      end

      Sync do |task|
        server = Server.new(
          zone:, zone_source:, listen: config.listen, udp_payload_size: config.udp_payload_size,
          max_connections: config.max_connections, idle_timeout: config.idle_timeout, tls:,
          doq_max_streams: config.doq_max_streams
        ).start(task)

        while (byte = reader.read(1))
          if byte == SIGNALS.fetch("HUP")
            server.reload
          else
            Console.info(self, "server.stopping", signal: SIGNALS.key(byte))
            server.shutdown
            break
          end
        end
      end
    ensure
      previous&.each { |signal, handler| Signal.trap(signal, handler || "DEFAULT") }
      reader&.close
      writer&.close
    end
  end
end
