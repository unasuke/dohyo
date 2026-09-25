# frozen_string_literal: true

module Dohyo
  # Counters, gauges and histograms, written out in the Prometheus text format (version 0.0.4).
  #
  # The series are few and fixed, so this replaces a metrics library. Label values are rounded to fixed sets (see
  # QTYPES) so that the number of series never grows with what clients send.
  class Metrics
    CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

    TRANSPORTS = %w[udp tcp dot doq].freeze
    RCODES = %w[NOERROR NXDOMAIN SERVFAIL REFUSED FORMERR NOTIMP BADVERS].freeze

    # Types the zone can hold, plus ANY; everything else is "other".
    QTYPES = {1 => "A", 2 => "NS", 6 => "SOA", 28 => "AAAA", 65 => "HTTPS", 255 => "ANY"}.freeze

    QUERY_DURATION_BUCKETS = [0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.05, 0.1].freeze

    Definition = Data.define(:name, :type, :help)

    DEFINITIONS = [
      Definition.new("dohyo_queries_total", :counter, "Queries answered, by transport, question type and RCODE."),
      Definition.new("dohyo_query_duration_seconds", :histogram, "Time from receiving a query to having its response, by transport."),
      Definition.new("dohyo_responses_truncated_total", :counter, "UDP responses truncated to fit the size limit."),
      Definition.new("dohyo_queries_dropped_total", :counter, "Messages not answered: too short for a header, or a response."),
      Definition.new("dohyo_connections_opened_total", :counter, "TCP, DoT and DoQ connections opened."),
      Definition.new("dohyo_connections_closed_total", :counter, "TCP, DoT and DoQ connections closed, by reason."),
      Definition.new("dohyo_connections_active", :gauge, "TCP, DoT and DoQ connections open now."),
      Definition.new("dohyo_zone_reloads_total", :counter, "Zone reloads, by result."),
      Definition.new("dohyo_zone_serial", :gauge, "The SOA serial of the zone being served."),
      Definition.new("dohyo_zone_loaded_timestamp_seconds", :gauge, "When the zone being served was loaded."),
      Definition.new("dohyo_build_info", :gauge, "Always 1; the labels describe the build.")
    ].freeze

    Histogram = Struct.new(:buckets, :sum, :count)

    def initialize
      @mutex = Mutex.new
      @values = Hash.new { |hash, name| hash[name] = {} }
    end

    def self.qtype_label(qtype) = QTYPES.fetch(qtype, "other")

    # Count one answered query and how long it took.
    def query(transport:, qtype:, rcode:, duration:, truncated: false)
      increment("dohyo_queries_total", transport:, qtype: Metrics.qtype_label(qtype), rcode:)
      observe("dohyo_query_duration_seconds", duration, QUERY_DURATION_BUCKETS, transport:)
      increment("dohyo_responses_truncated_total") if truncated
    end

    def dropped(transport:, reason:)
      increment("dohyo_queries_dropped_total", transport:, reason: reason.to_s)
    end

    def connection_opened(transport:)
      increment("dohyo_connections_opened_total", transport:)
      add("dohyo_connections_active", 1, transport:)
    end

    def connection_closed(transport:, reason:)
      increment("dohyo_connections_closed_total", transport:, reason:)
      add("dohyo_connections_active", -1, transport:)
    end

    # Zero the series that rate() should see from the start: every RCODE of each listening transport.
    def start(transports:, version:, ruby:)
      transports.uniq.each do |transport|
        RCODES.each { add("dohyo_queries_total", 0, transport:, qtype: "A", rcode: it) }
        add("dohyo_connections_active", 0, transport:) unless transport == "udp"
      end
      %w[success failure].each { add("dohyo_zone_reloads_total", 0, result: it) }
      set("dohyo_build_info", 1, version:, ruby:)
    end

    def zone_loaded(serial:, at: Time.now)
      set("dohyo_zone_serial", serial)
      set("dohyo_zone_loaded_timestamp_seconds", at.to_f)
    end

    def zone_reload(result:)
      increment("dohyo_zone_reloads_total", result:)
    end

    # @returns [Numeric, nil] The value of a counter or gauge, for tests.
    def value(name, **labels)
      @mutex.synchronize { @values.dig(name, labels) }
    end

    # The Prometheus text exposition format.
    def render
      @mutex.synchronize do
        DEFINITIONS.flat_map do |definition|
          series = @values.fetch(definition.name, {})
          next [] if series.empty?

          ["# HELP #{definition.name} #{definition.help}", "# TYPE #{definition.name} #{definition.type}",
            *series.sort_by { |labels, _| labels.to_a }.flat_map { |labels, value| lines(definition, labels, value) }]
        end.join("\n") + "\n"
      end
    end

    private

    def increment(name, **labels) = add(name, 1, **labels)

    def add(name, amount, **labels)
      @mutex.synchronize do
        series = @values[name]
        series[labels] = series.fetch(labels, 0) + amount
      end
    end

    def set(name, value, **labels)
      @mutex.synchronize { @values[name][labels] = value }
    end

    def observe(name, value, bounds, **labels)
      @mutex.synchronize do
        histogram = (@values[name][labels] ||= Histogram.new(bounds.to_h { [it, 0] }, 0.0, 0))
        histogram.buckets.each_key { |bound| histogram.buckets[bound] += 1 if value <= bound }
        histogram.sum += value
        histogram.count += 1
      end
    end

    def lines(definition, labels, value)
      name = definition.name
      return ["#{name}#{format_labels(labels)} #{format_number(value)}"] unless value.is_a?(Histogram)

      value.buckets.map { |bound, count| "#{name}_bucket#{format_labels(labels.merge(le: format_number(bound)))} #{count}" } +
        ["#{name}_bucket#{format_labels(labels.merge(le: "+Inf"))} #{value.count}",
          "#{name}_sum#{format_labels(labels)} #{format_number(value.sum)}",
          "#{name}_count#{format_labels(labels)} #{value.count}"]
    end

    def format_labels(labels)
      return "" if labels.empty?

      "{" + labels.map { |key, value| %(#{key}="#{escape(value.to_s)}") }.join(",") + "}"
    end

    # Label values: backslash, double quote and line feed are escaped.
    def escape(value) = value.gsub(/[\\"\n]/) { (it == "\n") ? "\\n" : "\\#{it}" }

    # Ruby's Integer#to_s and Float#to_s (including "1.0e-05") are valid Prometheus numbers.
    def format_number(value) = value.to_s
  end
end
