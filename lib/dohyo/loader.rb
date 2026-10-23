# frozen_string_literal: true

require "resolv"
require "dns/zonefile"
require "console"

require_relative "errors"
require_relative "zone"

module Dohyo
  # Reads a BIND zone file with dns-zonefile, validates it, and builds a Zone.
  #
  # This is the only file that depends on dns-zonefile.
  module Loader
    SOA = Resolv::DNS::Resource::IN::SOA::TypeValue
    NS = Resolv::DNS::Resource::IN::NS::TypeValue
    A = Resolv::DNS::Resource::IN::A::TypeValue
    AAAA = Resolv::DNS::Resource::IN::AAAA::TypeValue
    HTTPS = Resolv::DNS::Resource::IN::HTTPS::TypeValue

    # The record types dohyo serves. dns-zonefile can parse more; anything else is rejected.
    SUPPORTED_TYPES = {
      "DNS::Zonefile::SOA" => SOA,
      "DNS::Zonefile::NS" => NS,
      "DNS::Zonefile::A" => A,
      "DNS::Zonefile::AAAA" => AAAA,
      "DNS::Zonefile::HTTPS" => HTTPS
    }.freeze

    # RFC 2181 §8
    MAX_TTL = 2**31 - 1

    # SvcParamKeys with a presentation format dohyo understands (RFC 9460 §14.3.2, RFC 9461 §5).
    SVC_PARAM_KEYS = {
      "mandatory" => 0,
      "alpn" => 1,
      "no-default-alpn" => 2,
      "port" => 3,
      "ipv4hint" => 4,
      "ech" => 5,
      "ipv6hint" => 6,
      "dohpath" => 7
    }.freeze

    # Where a zone comes from, so that it can be read again on reload.
    Source = Data.define(:origin, :path) do
      def load = Loader.load(origin:, path:)
    end

    # @parameter origin [String] The zone apex from the configuration, absolute (with a trailing dot).
    # @parameter path [String] The zone file.
    # @returns [Zone]
    def self.load(origin:, path:)
      # UTF-8 explicitly: under the C locale (as under systemd on a minimal system) Ruby would read the file as
      # US-ASCII, and a comment in any other language would break parsing.
      text = begin
        File.read(path, encoding: Encoding::UTF_8)
      rescue SystemCallError => error
        raise ZoneError.new("cannot read the zone file: #{error.message}", path:)
      end
      raise ZoneError.new("the zone file is not valid UTF-8", path:) unless text.valid_encoding?

      parse(text, origin:, path:)
    end

    # @returns [Zone]
    def self.parse(text, origin:, path: nil)
      Builder.new(text, origin:, path:).build
    end

    # Validates one zone file and converts it. Every failure raises ZoneError naming the check that failed.
    class Builder
      def initialize(text, origin:, path:)
        @text = text
        @origin = origin.downcase(:ascii)
        @path = path
      end

      def build
        check_directives
        check_ttl_directives
        check_origin_directives
        zonefile = parse_zonefile

        records = zonefile.records.map { |record| convert(record) }
        check_apex(records)

        Zone.new(origin: @origin, rrsets: rrsets(records))
      end

      private

      def fail!(message)
        raise ZoneError.new(message, path: @path)
      end

      # dns-zonefile 1.3.0 reads any other directive, $INCLUDE among them, as a variable and goes on without reading
      # a file: the records it was meant to bring in would be missing without a word.
      def check_directives
        @text.each_line.with_index(1) do |line, number|
          next unless (match = line.match(/\A\s*\$([^\s;]+)/))

          name = match[1]
          fail!("line #{number}: $#{name} is not supported (only $ORIGIN and $TTL are)") unless %w[ORIGIN TTL].include?(name.upcase(:ascii))
        end
      end

      # dns-zonefile 1.3.0 reads "$TTL 1h" as 1 second (a record's own TTL field understands units). Accept only
      # plain seconds in $TTL, so that a unit can never silently shorten every TTL.
      def check_ttl_directives
        @text.each_line.with_index(1) do |line, number|
          next unless (match = line.match(/\A\s*\$TTL\s+(\S+)/i))

          value = match[1].sub(/;.*\z/, "")
          fail!("line #{number}: $TTL must be a number of seconds, not #{value.inspect}") unless value.match?(/\A\d+\z/)
        end
      end

      # The same as DNS::Zonefile.load, but also counts the SOA entries: dns-zonefile 1.3.0 keeps only the first SOA
      # and silently drops the others, so a second SOA would otherwise go unnoticed.
      def parse_zonefile
        entries = DNS::Zonefile.parse(@text).entries
        soa_count = entries.count { |entry| entry.parse_type == :soa || (entry.parse_type == :record && entry.record_type == "SOA") }
        fail!("the zone file must have exactly one SOA, found #{soa_count}") if soa_count > 1

        DNS::Zonefile::Zone.new(entries)
      rescue DNS::Zonefile::ParsingError => error
        fail!("cannot parse the zone file: #{error.message}")
      end

      # Without $ORIGIN, dns-zonefile resolves "@" to "." and "www" to "www.", so $ORIGIN is mandatory. Its
      # DNS::Zonefile::Zone#origin is never set, so the directive is read from the text. Every $ORIGIN must name
      # the configured origin; names written before the first one end up outside the zone and are rejected later.
      def check_origin_directives
        origins = @text.each_line.with_index(1).filter_map do |line, number|
          match = line.match(/\A\s*\$ORIGIN\s+([^\s;]+)/i)
          [match[1], number] if match
        end

        fail!("$ORIGIN is missing") if origins.empty?

        origins.each do |value, number|
          fail!("line #{number}: $ORIGIN #{value} does not match the configured origin #{@origin}") if value.downcase(:ascii) != @origin
        end
      end

      Record = Data.define(:owner, :type, :ttl, :resource)

      def convert(record)
        type = SUPPORTED_TYPES.fetch(record.class.name) do
          fail!("unsupported record type #{record.class.name.split("::").last} at #{owner_of(record)}")
        end

        owner = owner_of(record)
        key = Zone.key(Resolv::DNS::Name.create(owner))
        label = key.split(".").first

        fail!("#{owner} is outside the zone #{@origin}") unless Zone.within?(key, @origin)
        fail!("#{owner}: wildcards are not supported") if label == "*"
        fail!("#{owner}: TTL #{record.ttl} is out of range (0..#{MAX_TTL})") unless (0..MAX_TTL).cover?(record.ttl)

        Record.new(owner: key, type:, ttl: record.ttl, resource: resource_of(record, type, owner))
      end

      def owner_of(record)
        record.is_a?(DNS::Zonefile::SOA) ? record.origin : record.host
      end

      def resource_of(record, type, owner)
        case type
        when SOA
          Resolv::DNS::Resource::IN::SOA.new(
            name(record.nameserver), name(record.responsible_party),
            record.serial, record.refresh_time, record.retry_time, record.expiry_time, record.nxttl
          )
        when NS
          Resolv::DNS::Resource::IN::NS.new(name(record.domainname))
        when A
          Resolv::DNS::Resource::IN::A.new(address(record.address, :ipv4, owner))
        when AAAA
          Resolv::DNS::Resource::IN::AAAA.new(address(record.address, :ipv6, owner))
        when HTTPS
          Resolv::DNS::Resource::IN::HTTPS.new(record.priority.to_i, name(record.target_name), svc_params(record.svcparams, owner))
        end
      end

      def name(text)
        Resolv::DNS::Name.create(text)
      end

      ADDRESS_FORMATS = {ipv4: Resolv::IPv4::Regex, ipv6: Resolv::IPv6::Regex}.freeze

      def address(text, family, owner)
        fail!("#{owner}: #{text.inspect} is not an #{family.to_s.sub("ip", "IP")} address") unless ADDRESS_FORMATS.fetch(family).match?(text)

        text
      end

      # Converts dns-zonefile's {"key" => "value"} into Resolv::DNS::SvcParams. resolv sorts the keys by number when
      # encoding, as RFC 9460 §2.2 requires.
      def svc_params(params, owner)
        seen = {}

        converted = (params || {}).map do |key_name, value|
          value = value.to_s
          fail!("#{owner}: #{key_name}: escapes (\\) in SvcParam values are not supported") if value.include?("\\")

          number = svc_param_number(key_name, owner)
          fail!("#{owner}: SvcParamKey #{number} appears more than once") if seen.key?(number)
          seen[number] = true

          svc_param(number, value, owner)
        end

        Resolv::DNS::SvcParams.new(converted)
      end

      def svc_param_number(key_name, owner)
        if (match = key_name.match(/\Akey(\d+)\z/))
          number = Integer(match[1], 10)
          fail!("#{owner}: #{key_name} is out of range") unless (0..65535).cover?(number)
          number
        else
          SVC_PARAM_KEYS.fetch(key_name) { fail!("#{owner}: unknown SvcParamKey #{key_name}") }
        end
      end

      def svc_param(number, value, owner)
        list = -> { value.split(",", -1).tap { |items| fail!("#{owner}: empty value in #{value.inspect}") if items.empty? || items.any?(&:empty?) } }

        case number
        when 0
          Resolv::DNS::SvcParam::Mandatory.new(list.call.map { svc_param_number(it, owner) })
        when 1
          Resolv::DNS::SvcParam::ALPN.new(list.call)
        when 2
          fail!("#{owner}: no-default-alpn takes no value") unless value.empty?
          Resolv::DNS::SvcParam::NoDefaultALPN.new
        when 3
          fail!("#{owner}: port must be 0..65535, not #{value.inspect}") unless value.match?(/\A\d+\z/) && value.to_i <= 65535
          Resolv::DNS::SvcParam::Port.new(value.to_i)
        when 4
          Resolv::DNS::SvcParam::IPv4Hint.new(list.call.map { Resolv::IPv4.create(address(it, :ipv4, owner)) })
        when 5
          bytes = value.unpack1("m0")
          Resolv::DNS::SvcParam::Generic.create(5).new(bytes)
        when 6
          Resolv::DNS::SvcParam::IPv6Hint.new(list.call.map { Resolv::IPv6.create(address(it, :ipv6, owner)) })
        when 7
          Resolv::DNS::SvcParam::DoHPath.new(value)
        else
          Resolv::DNS::SvcParam::Generic.create(number).new(value.b)
        end
      rescue ArgumentError
        fail!("#{owner}: invalid value #{value.inspect} for SvcParamKey #{number}")
      end

      def check_apex(records)
        records.each do |record|
          next if record.owner == @origin

          fail!("#{record.owner}: SOA is only allowed at the apex") if record.type == SOA
          # An NS below the apex would be a delegation, which is not supported:
          fail!("#{record.owner}: NS is only allowed at the apex") if record.type == NS
        end

        apex = records.select { it.owner == @origin }
        fail!("the apex #{@origin} must have exactly one SOA") unless apex.count { it.type == SOA } == 1
        fail!("the apex #{@origin} must have at least one NS") if apex.none? { it.type == NS }
      end

      # Groups records into RRsets. RFC 2181 §5.2: all RRs of an RRset share one TTL; when they differ, use the
      # smallest and warn. Identical RRs are merged (an RRset is a set).
      def rrsets(records)
        result = Hash.new { |hash, name| hash[name] = {} }

        records.group_by { [it.owner, it.type] }.each do |(owner, type), group|
          ttls = group.map(&:ttl).uniq
          ttl = ttls.min

          if ttls.size > 1
            Console.warn(self, "zone.ttl_mismatch", name: owner, type:, ttls:, chosen: ttl)
          end

          resources = group.map(&:resource).uniq { Zone.rdata(it) }
          result[owner][type] = [ttl, resources]
        end

        result
      end
    end
  end
end
