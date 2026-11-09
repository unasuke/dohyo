# frozen_string_literal: true

require "resolv"

require_relative "errors"
require_relative "zone"
require_relative "edns"
require_relative "responder"

module Dohyo
  # The entry point of the resolution logic: query bytes in, response bytes and a breakdown for metrics out.
  #
  # It has no I/O. Transports call it with `transport: :udp` (responses are size-limited and truncated) or
  # `transport: :stream` (TCP, DoT and DoQ; never truncated).
  class Engine
    RCODE_NAMES = {
      0 => "NOERROR",
      1 => "FORMERR",
      2 => "SERVFAIL",
      3 => "NXDOMAIN",
      4 => "NOTIMP",
      5 => "REFUSED",
      16 => "BADVERS"
    }.freeze

    FORMERR = Resolv::DNS::RCode::FormErr
    SERVFAIL = Resolv::DNS::RCode::ServFail
    NOTIMP = Resolv::DNS::RCode::NotImp
    REFUSED = Resolv::DNS::RCode::Refused
    BADVERS = 16

    IN = Resolv::DNS::Resource::IN::ClassValue
    # IXFR (251, RFC 1995) and AXFR (252, RFC 5936). resolv has no IN::AXFR/IXFR constants.
    ZONE_TRANSFER_TYPES = [251, 252].freeze

    # RFC 1035 §4.2.1: without EDNS, UDP messages are limited to 512 bytes.
    CLASSIC_UDP_SIZE = 512
    HEADER_SIZE = 12

    # @attribute bytes [String, nil] The response, or nil when nothing should be sent.
    # @attribute rcode [String, nil] The RCODE name for metrics (BADVERS is distinct from NOERROR). nil when dropped.
    # @attribute qname [String, nil] The question name as received (for logs). nil when unreadable.
    # @attribute qtype [Integer, nil] The question type number, before any rounding. nil when unreadable.
    # @attribute truncated [Boolean] Whether the UDP response was truncated.
    # @attribute dropped_reason [Symbol, nil] :too_short or :is_response when nothing is sent.
    # @attribute edns_option_codes [Array<Integer>] Option codes in the query's OPT; empty without OPT.
    # @attribute error [StandardError, nil] The unexpected error that caused SERVFAIL; the transport logs it.
    Result = Data.define(:bytes, :rcode, :qname, :qtype, :truncated, :dropped_reason, :edns_option_codes, :error)

    def initialize(zone_provider:, udp_payload_size:)
      @zone_provider = zone_provider
      @udp_payload_size = udp_payload_size
      @responder = Responder.new
    end

    # @parameter bytes [String] A DNS message as received, without any transport framing.
    # @parameter transport [Symbol] :udp or :stream.
    def call(bytes, transport:)
      raise ArgumentError, "unknown transport: #{transport.inspect}" unless %i[udp stream].include?(transport)

      bytes = bytes.b
      return dropped(:too_short) if bytes.bytesize < HEADER_SIZE

      id, flags = bytes.unpack("nn")
      # A response (QR=1) is never answered, so that two servers cannot loop:
      return dropped(:is_response) if flags[15] == 1

      # Take the zone once, so that a reload in the middle of a query cannot mix two versions:
      zone = @zone_provider.call

      begin
        query = Resolv::DNS::Message.decode(bytes)
      rescue # resolv raises DecodeError, but also ArgumentError or Encoding::CompatibilityError
        return finish(header_only_error(id, flags, FORMERR), nil, transport)
      end

      process(query, zone, transport)
    end

    private

    def process(query, zone, transport)
      question = (query.question.size == 1) ? query.question.fetch(0) : nil
      qname = question&.first&.to_s
      qtype = question&.last&.const_get(:TypeValue)
      edns = nil

      begin
        opt_count = EDNS.count(query)
        edns = EDNS.extract(query) if opt_count == 1

        # Before FORMERR, so that an unknown opcode is NOTIMP whatever the sections hold (RFC 8906 §8.1.4). The
        # question is copied only when there is exactly one; with more than one OPT, none is added.
        if query.opcode != Resolv::DNS::OpCode::Query
          return finish(error_response(query, NOTIMP, question: !question.nil?), edns, transport, qname:, qtype:)
        end

        # RFC 6891 §6.1.1: more than one OPT is FORMERR. A TC=1 query also lands here: resolv stops decoding after
        # the header, leaving no question.
        return finish(error_response(query, FORMERR, question: false), nil, transport, qname:, qtype:) if query.question.size != 1 || opt_count > 1

        response =
          if edns && edns.version > 0
            # RFC 6891 §6.1.3: answer BADVERS with an OPT of the highest version supported.
            error_response(query, BADVERS)
          else
            answer(query, zone)
          end

        finish(response, edns, transport, qname:, qtype:)
      rescue => error
        finish(error_response(query, SERVFAIL), edns, transport, qname:, qtype:, error:)
      end
    end

    def answer(query, zone)
      qname, type_class = query.question.fetch(0)

      return error_response(query, REFUSED) if type_class::ClassValue != IN
      # Zone transfers are not supported:
      return error_response(query, REFUSED) if ZONE_TRANSFER_TYPES.include?(type_class::TypeValue)
      # Not authoritative for the name:
      return error_response(query, REFUSED) unless zone.contains?(Zone.key(qname))

      @responder.call(query, zone)
    end

    # An error response: QR=1, AA=0, ID, opcode and RD copied, the question copied (unless it is unusable).
    def error_response(query, rcode, question: true)
      response = Resolv::DNS::Message.new(query.id)
      response.qr = 1
      response.opcode = query.opcode
      response.rd = query.rd
      response.rcode = rcode
      query.question.each { |name, type_class| response.add_question(name, type_class) } if question
      response
    end

    # A FORMERR for a message that could not be decoded: only the header is meaningful.
    def header_only_error(id, flags, rcode)
      response = Resolv::DNS::Message.new(id)
      response.qr = 1
      response.opcode = (flags >> 11) & 0xf
      response.rd = (flags >> 8) & 1
      response.rcode = rcode
      response
    end

    # Add the OPT, encode, and apply the UDP size limit.
    def finish(response, edns, transport, qname: nil, qtype: nil, error: nil)
      rcode = response.rcode
      # Only add an OPT when the query had one (RFC 6891 §7). BADVERS keeps its upper bits in the OPT TTL.
      EDNS.append(response, udp_payload_size: @udp_payload_size, rcode:) if edns

      bytes = response.encode
      truncated = false

      if transport == :udp && bytes.bytesize > udp_limit(edns)
        bytes = truncate(response, edns, rcode).encode
        truncated = true
      end

      Result.new(
        bytes:,
        rcode: RCODE_NAMES.fetch(rcode),
        qname:,
        qtype:,
        truncated:,
        dropped_reason: nil,
        edns_option_codes: edns ? edns.option_codes : [],
        error:
      )
    rescue => encode_error
      # Encoding failed (for example a record that resolv cannot encode); fall back to a bare SERVFAIL, which has
      # nothing left that could fail to encode.
      fallback = Resolv::DNS::Message.new(response.id)
      fallback.qr = 1
      fallback.opcode = response.opcode
      fallback.rd = response.rd
      fallback.rcode = SERVFAIL
      Result.new(bytes: fallback.encode, rcode: "SERVFAIL", qname:, qtype:, truncated: false, dropped_reason: nil, edns_option_codes: [], error: error || encode_error)
    end

    # The largest UDP response: 512 without EDNS; otherwise the client's size (at least 512) capped by ours.
    def udp_limit(edns)
      return CLASSIC_UDP_SIZE unless edns

      # The configured size is at least 512, so the range is never empty.
      edns.udp_payload_size.clamp(CLASSIC_UDP_SIZE, @udp_payload_size)
    end

    # Keep the header (with TC=1), the question and the OPT; drop every RR otherwise (no partial truncation).
    def truncate(response, edns, rcode)
      truncated = Resolv::DNS::Message.new(response.id)
      truncated.qr = 1
      truncated.opcode = response.opcode
      truncated.aa = response.aa
      truncated.tc = 1
      truncated.rd = response.rd
      truncated.rcode = rcode
      response.question.each { |name, type_class| truncated.add_question(name, type_class) }
      EDNS.append(truncated, udp_payload_size: @udp_payload_size, rcode:) if edns
      truncated
    end

    def dropped(reason)
      Result.new(bytes: nil, rcode: nil, qname: nil, qtype: nil, truncated: false, dropped_reason: reason, edns_option_codes: [], error: nil)
    end
  end
end
