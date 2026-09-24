# frozen_string_literal: true

require "resolv"

module Dohyo
  # Reading and writing the EDNS(0) OPT pseudo-RR (RFC 6891).
  #
  # resolv has no OPT class: an OPT RR decodes into a generic resource of type 41 whose CLASS holds the UDP payload
  # size and whose TTL packs the extended RCODE, the version and the DO bit (RFC 6891 §6.1.3).
  module EDNS
    TYPE = 41

    # @attribute options [Array(Array(Integer, String))] Option codes and their data, in the order received.
    Options = Data.define(:udp_payload_size, :extended_rcode, :version, :dnssec_ok, :options) do
      def option_codes
        options.map(&:first)
      end
    end

    def self.opt_record?(record)
      record.class::TypeValue == TYPE
    end

    # @returns [Integer] The number of OPT RRs in the additional section.
    def self.count(message)
      message.additional.count { |_, _, record| opt_record?(record) }
    end

    # @returns [Options, nil] The first OPT RR of the message, or nil when there is none.
    def self.extract(message)
      _, ttl, record = message.additional.find { |_, _, record| opt_record?(record) }
      return nil unless record

      Options.new(
        udp_payload_size: record.class::ClassValue,
        extended_rcode: (ttl >> 24) & 0xff,
        version: (ttl >> 16) & 0xff,
        dnssec_ok: ttl[15] == 1,
        options: parse_options(record.data.b)
      )
    end

    # Append an OPT RR with version 0, DO=0 and no options. The upper 8 bits of rcode go into the OPT TTL and the
    # lower 4 bits into the header: resolv masks the header RCODE with 15 when encoding.
    def self.append(message, udp_payload_size:, rcode:)
      record = Resolv::DNS::Resource.get_class(TYPE, udp_payload_size).new("".b)
      ttl = ((rcode >> 4) & 0xff) << 24

      message.rcode = rcode & 0xf
      message.add_additional(Resolv::DNS::Name.create("."), ttl, record)
      message
    end

    # RFC 6891 §6.1.2: OPTION-CODE (2), OPTION-LENGTH (2), OPTION-DATA. A truncated trailing option is ignored.
    def self.parse_options(data)
      options = []
      offset = 0

      while offset + 4 <= data.bytesize
        code, length = data.unpack("nn", offset:)
        offset += 4
        break if offset + length > data.bytesize

        options << [code, data.byteslice(offset, length)]
        offset += length
      end

      options
    end
    private_class_method :parse_options
  end
end
