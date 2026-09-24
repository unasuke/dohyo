# frozen_string_literal: true

require "resolv"

require_relative "errors"
require_relative "zone"

module Dohyo
  # Builds an authoritative response for a query whose name is inside the zone.
  #
  # Engine has already checked the query: one question, class IN, a type other than AXFR/IXFR, and a name that the
  # zone contains. There are no wildcards, CNAMEs or delegations, so RFC 1034 §4.3.2 reduces to "the name exists or
  # it does not".
  class Responder
    ANY = Resolv::DNS::Resource::IN::ANY::TypeValue

    def call(query, zone)
      qname, type_class = query.question.fetch(0)
      key = Zone.key(qname)
      qtype = type_class::TypeValue

      response = Resolv::DNS::Message.new(query.id)
      response.qr = 1
      response.opcode = query.opcode
      response.rd = query.rd
      response.ra = 0
      # The question is echoed as received, including its case:
      response.add_question(qname, type_class)

      raise ProtocolError, "#{key} is outside #{zone.origin}" unless zone.contains?(key)

      unless zone.name_exists?(key)
        return negative(response, zone, rcode: Resolv::DNS::RCode::NXDomain)
      end

      # RFC 8482 §4.2: answer ANY with a single RRset. The one with the smallest type number is chosen.
      type = (qtype == ANY) ? zone.types_at(key).first : qtype
      ttl, records = zone.rrset(key, type) if type

      # NODATA: the name exists (possibly as an empty non-terminal, RFC 8020) but has no RRset of this type.
      return negative(response, zone, rcode: Resolv::DNS::RCode::NoError) unless records

      response.aa = 1
      response.rcode = Resolv::DNS::RCode::NoError
      # The owner is the question name, so name compression points back at it and preserves its case.
      records.each { |record| response.add_answer(qname, ttl, record) }
      response
    end

    private

    # RFC 2308 §3: negative responses carry the apex SOA in the authority section, with the negative TTL.
    def negative(response, zone, rcode:)
      response.aa = 1
      response.rcode = rcode
      response.add_authority(Resolv::DNS::Name.create(zone.origin), zone.negative_ttl, zone.soa)
      response
    end
  end
end
