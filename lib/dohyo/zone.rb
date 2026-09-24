# frozen_string_literal: true

require "resolv"

module Dohyo
  # An immutable index of one zone: names and types to RRsets.
  #
  # Names are lowercase absolute names with a trailing dot (String), types are type numbers (Integer).
  # Callers normalize their arguments; see Zone.key.
  class Zone
    SOA_TYPE = Resolv::DNS::Resource::IN::SOA::TypeValue

    # The lookup key of a Resolv::DNS::Name: lowercase (ASCII only) labels joined with dots, with a trailing dot.
    # Dots and backslashes inside a label are escaped so that a single label such as "a.b" (possible on the wire)
    # never collides with the two labels "a" and "b".
    def self.key(name)
      labels = name.to_a.map { |label| label.to_s.b.downcase(:ascii).gsub(/[.\\]/) { "\\#{it}" } }
      labels.empty? ? "." : "#{labels.join(".")}."
    end

    # The rdata of a record in wire format. The owner is the root, so no name in the rdata is compressed.
    def self.rdata(record)
      message = Resolv::DNS::Message.new(0)
      message.add_answer(Resolv::DNS::Name.create("."), 0, record)
      # Header (12) + owner "." (1) + type, class, TTL and RDLENGTH (10):
      message.encode.byteslice(23..) || "".b
    end

    attr_reader :origin, :soa, :serial, :negative_ttl

    # @parameter origin [String] The zone apex as a key.
    # @parameter rrsets [Hash{String => Hash{Integer => [Integer, Array<Resolv::DNS::Resource>]}}]
    #   Owner key to type number to [TTL, RRs]. The loader has already validated and normalized the data.
    def initialize(origin:, rrsets:)
      @origin = origin
      @rrsets = rrsets.to_h { |name, by_type| [name, by_type.sort.to_h] }

      soa_ttl, soa_records = @rrsets.fetch(origin).fetch(SOA_TYPE)
      @soa = soa_records.fetch(0)
      @serial = @soa.serial
      # RFC 2308 §3: the TTL of the SOA in a negative response is the minimum of the SOA's own TTL and MINIMUM.
      @negative_ttl = [soa_ttl, @soa.minimum].min

      @names = existing_names
      @fingerprint = build_fingerprint

      Ractor.make_shareable(self)
    end

    # @returns [Array(Integer, Array<Resolv::DNS::Resource>), nil] The TTL and the RRs.
    def rrset(name, type)
      @rrsets.dig(name, type)
    end

    # @returns [Array<Integer>] The type numbers the name owns, in ascending order.
    def types_at(name)
      @rrsets.fetch(name, {}).keys
    end

    # True for names that own records and for empty non-terminals (RFC 8020).
    def name_exists?(name)
      @names.include?(name)
    end

    # True when the name is the apex or below it.
    def contains?(name)
      name == @origin || name.end_with?(".#{@origin}")
    end

    # Equal when the origin and every RR (owner, type, TTL, rdata in wire format) match.
    # Resolv::DNS::Resource#== cannot be used: IN::HTTPS compares SvcParams by identity.
    def ==(other)
      other.is_a?(Zone) && origin == other.origin && fingerprint == other.fingerprint
    end

    alias_method :eql?, :==

    def hash
      [origin, fingerprint].hash
    end

    protected

    attr_reader :fingerprint

    private

    def existing_names
      names = Set.new

      @rrsets.each_key do |name|
        # Every ancestor down to the apex exists, even when it owns no records (empty non-terminal):
        current = name
        until names.include?(current)
          names << current
          break if current == @origin

          current = current.sub(/\A(?:[^.\\]|\\.)*\./, "")
        end
      end

      names
    end

    def build_fingerprint
      set = Set.new

      @rrsets.each do |name, by_type|
        by_type.each do |type, (ttl, records)|
          records.each do |record|
            set << [name, type, ttl, Zone.rdata(record)]
          end
        end
      end

      set
    end
  end
end
