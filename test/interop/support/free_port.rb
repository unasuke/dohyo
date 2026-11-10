# frozen_string_literal: true

require "socket"

module FreePort
  # A loopback port free for both UDP and TCP, for a server that needs the same port for both. The OS may hand it to
  # someone else before the server binds it; the server then fails to start.
  def self.pick
    loop do
      tcp = Socket.new(:INET, :STREAM)
      tcp.bind(Addrinfo.tcp("127.0.0.1", 0))
      port = tcp.local_address.ip_port
      udp = Socket.new(:INET, :DGRAM)
      begin
        udp.bind(Addrinfo.udp("127.0.0.1", port))
        return port
      rescue Errno::EADDRINUSE
        next
      ensure
        udp.close
        tcp.close
      end
    end
  end
end
