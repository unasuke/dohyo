# frozen_string_literal: true

require "ipaddr"
require "resolv"

# One line per RR, "owner TTL IN TYPE RDATA", in a form that does not depend on how the RR was written:
#
# - names are lowercase and absolute;
# - A and AAAA addresses are written as IPAddr#to_s;
# - SOA numbers are decimal;
# - HTTPS SvcParams are written "key<number>=<value>" in the order of the wire format, which RFC 9460 §2.2 requires
#   to be ascending. Lists are comma-separated: mandatory as key numbers, alpn as protocol IDs, the hints as
#   addresses. ech is base64; any other value is its bytes as text. no-default-alpn is "key2=".
#
# Lines come from a Dohyo::Zone (what dohyo serves) or from the output of named-checkzone -D. Values with escapes
# are not supported on either side.
module CanonicalRR
  TYPES = {6 => "SOA", 2 => "NS", 1 => "A", 28 => "AAAA", 65 => "HTTPS"}.freeze

  # The SvcParamKey names BIND prints (RFC 9460 §14.3.2). Keys without a name are printed as key<number>.
  SVC_PARAM_KEYS = {
    "mandatory" => 0, "alpn" => 1, "no-default-alpn" => 2, "port" => 3, "ipv4hint" => 4, "ech" => 5, "ipv6hint" => 6
  }.freeze

  module_function

  # @parameter zone [Dohyo::Zone]
  # @returns [Array<String>]
  def from_zone(zone)
    zone.each_rrset.flat_map do |name, type, ttl, records|
      records.map { |record| line(name, ttl, TYPES.fetch(type), rdata_of(type, record)) }
    end
  end

  # @parameter text [String] The output of named-checkzone -D -o -.
  # @returns [Array<String>]
  def from_bind(text)
    text.each_line.filter_map do |text_line|
      owner, ttl, klass, type, *rdata = text_line.split
      next unless klass == "IN"

      line(owner, Integer(ttl, 10), type, bind_rdata(type, rdata))
    end
  end

  def line(owner, ttl, type, rdata)
    [owner.downcase, ttl, "IN", type, rdata].join(" ")
  end

  def name(text)
    text = text.to_s.downcase
    text.end_with?(".") ? text : "#{text}."
  end

  def rdata_of(type, record)
    case type
    when 6
      [name(record.mname), name(record.rname), record.serial, record.refresh, record.retry, record.expire, record.minimum].join(" ")
    when 2
      name(record.name)
    when 1, 28
      IPAddr.new_ntoh(record.address.address).to_s
    when 65
      https_from_wire(Dohyo::Zone.rdata(record))
    end
  end

  # RFC 9460 §2.2: SvcPriority (2), TargetName (uncompressed), then SvcParams (key 2, length 2, value).
  def https_from_wire(wire)
    priority = wire.unpack1("n")
    offset = 2
    labels = []
    until (length = wire.getbyte(offset)).zero?
      labels << wire.byteslice(offset + 1, length)
      offset += 1 + length
    end
    offset += 1
    target = labels.empty? ? "." : "#{labels.join(".")}."

    params = []
    while offset < wire.bytesize
      key, length = wire.unpack("nn", offset:)
      params << "key#{key}=#{svc_value_from_wire(key, wire.byteslice(offset + 4, length))}"
      offset += 4 + length
    end

    [priority, name(target), *params].join(" ")
  end

  def svc_value_from_wire(key, value)
    case key
    when 0 then value.unpack("n*").join(",")
    when 1
      ids = []
      offset = 0
      while offset < value.bytesize
        length = value.getbyte(offset)
        ids << value.byteslice(offset + 1, length)
        offset += 1 + length
      end
      ids.join(",")
    when 2 then ""
    when 3 then value.unpack1("n").to_s
    when 4 then value.scan(/.{4}/mn).map { IPAddr.new_ntoh(it).to_s }.join(",")
    when 6 then value.scan(/.{16}/mn).map { IPAddr.new_ntoh(it).to_s }.join(",")
    when 5 then [value].pack("m0")
    else value
    end
  end

  def bind_rdata(type, fields)
    case type
    when "SOA"
      mname, rname, *numbers = fields
      [name(mname), name(rname), *numbers.map { Integer(it, 10) }].join(" ")
    when "NS"
      name(fields.fetch(0))
    when "A", "AAAA"
      IPAddr.new(fields.fetch(0)).to_s
    when "HTTPS"
      priority, target, *params = fields
      [Integer(priority, 10), name(target), *params.map { bind_svc_param(it) }].join(" ")
    else
      raise ArgumentError, "unexpected type #{type} in the output of named-checkzone"
    end
  end

  def bind_svc_param(param)
    key_name, value = param.split("=", 2)
    key = svc_key(key_name)
    value = value.to_s.delete_prefix('"').delete_suffix('"')

    value =
      case key
      when 0 then value.split(",").map { svc_key(it) }.join(",")
      when 4, 6 then value.split(",").map { IPAddr.new(it).to_s }.join(",")
      when 3 then Integer(value, 10).to_s
      else value
      end

    "key#{key}=#{value}"
  end

  def svc_key(key_name)
    SVC_PARAM_KEYS.fetch(key_name) { Integer(key_name.delete_prefix("key"), 10) }
  end
end
