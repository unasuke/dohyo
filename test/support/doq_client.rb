# frozen_string_literal: true

require "protocol/quic"
require "socket"

# A DoQ client on protocol-quic that can also send what a well-behaved client never would.
class DoQTestClient < Protocol::QUIC::Client
  class Stream < Protocol::QUIC::Stream
    def initialize(...)
      super
      @data = +"".b
      @done = Thread::Queue.new
    end

    def received(data, fin)
      @data << data
      @done << :fin if fin
    end

    def reset_received(error_code) = @done << [:reset, error_code]

    # @returns [String, Array, nil] The response data after FIN, [:reset, code], or nil on timeout.
    def wait(timeout: 3)
      result = @done.pop(timeout:)
      (result == :fin) ? @data : result
    end
  end

  QUIC_V1 = 1

  def self.connect(address, alpn: "doq")
    configuration = Protocol::QUIC::Configuration.new
    context = Protocol::QUIC::TLS::ClientContext.new
    context.add_protocol(alpn)

    remote = Protocol::QUIC::Address.resolve(address.ip_address, address.ip_port.to_s, address.afamily, Socket::SOCK_DGRAM, 0).first
    socket = Protocol::QUIC::Socket.new(address.afamily, Socket::SOCK_DGRAM, Socket::IPPROTO_UDP)
    socket.connect(remote)

    client = new(configuration, context, socket, remote, QUIC_V1)
    client.instance_variable_set(:@quic_socket, socket)
    client
  end

  def initialize(...)
    super
    @handshake = Thread::Queue.new
  end

  def create_stream(stream_id) = Stream.new(self, stream_id)

  def handshake_completed = @handshake << true

  # Runs the connection in the given task and waits for the handshake.
  # @returns [Boolean] Whether the handshake completed.
  def start(task)
    @runner = task.async { connect }
    !@handshake.pop(timeout: 3).nil?
  end

  def finished? = @runner.finished?

  # Sends raw stream data (the caller adds the length prefix) and FIN.
  def send_stream(data)
    stream = open_bidirectional_stream
    stream.write(data)
    stream.finish
    send_packets
    stream
  end

  def query(message) = send_stream([message.bytesize].pack("n") + message)

  # Waits for the CONNECTION_CLOSE from the server: [:application, code], [:transport, code] or nil.
  def wait_for_close(timeout: 3)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    until (error = remote_close_error) || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      sleep 0.02
    end
    error
  end

  def stop
    @runner&.stop
    @quic_socket&.close
  end
end
