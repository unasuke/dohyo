# frozen_string_literal: true

require "test_helper"
require "async"
require "json"
require "open3"
require "support/certificates"
require_relative "support/free_port"

# DoT and DoQ clients other than kdig against dohyo: q (DoT and DoQ) and dnsproxy (DoQ upstream), both Go with
# quic-go. The answers to the questions of cases 1, 3, 4, 5 and 28 must match what dohyo answers over UDP, and the
# queries of one client run must share one connection. The certificate is verified against a CA made on the spot,
# which Go reads from SSL_CERT_FILE.
class TestInteropClients < Minitest::Test
  include DohyoTestHelper

  BIG = "big.blog.example.com."
  # The questions of cases 1, 3, 4, 5 and 28. The UDP reference queries with EDNS (1232, as q does), so that the 40
  # A records of case 28 fit without truncation.
  QUESTIONS = {
    "1" => [ORIGIN, IN::SOA], "3" => [ORIGIN, IN::A], "4" => [ORIGIN, IN::AAAA], "5" => [ORIGIN, IN::HTTPS],
    "28" => [BIG, IN::A]
  }.freeze
  READY_TIMEOUT = 5
  AA = 0x0400

  def setup
    @certificates = TestCertificates.write
  end

  def teardown
    FileUtils.rm_rf(@certificates.directory) if @certificates
  end

  def test_q_over_dot
    skip "q is not installed" unless installed?("q")

    # dohyo sets no ALPN for DoT; q offers dot, and kdig (test_server.rb) offers none.
    with_server { |server, addresses| assert_q(server, "dot", "tls://127.0.0.1:#{addresses.fetch("dot").ip_port}", "--tls-next-protos=dot") }
  end

  def test_q_over_doq
    skip "q is not installed" unless installed?("q")

    with_server { |server, addresses| assert_q(server, "doq", "quic://127.0.0.1:#{addresses.fetch("doq").ip_port}") }
  end

  def test_dnsproxy_over_doq
    skip "dnsproxy is not installed" unless installed?("dnsproxy")

    with_server do |server, addresses|
      with_dnsproxy("quic://127.0.0.1:#{addresses.fetch("doq").ip_port}") do |proxy|
        QUESTIONS.each do |id, (name, type_class)|
          bytes = query_bytes(name, type_class, edns: 1232)
          expected = udp_exchange(addresses.fetch("udp"), bytes)
          # A proxy is not authoritative, so dnsproxy clears AA; everything else is dohyo's answer as it is.
          assert_equal without_aa(expected), without_aa(udp_exchange(proxy, bytes)), "case #{id}"
        end
      end

      assert_equal 1, server.metrics.value("dohyo_connections_opened_total", transport: "doq"), "dnsproxy keeps one connection"
    end
  end

  private

  def installed?(command) = system("which", command, out: File::NULL, err: File::NULL)

  def with_server
    tls = Dohyo::TLS.load(certificate_chain: @certificates.certificate_chain, private_key: @certificates.private_key)
    listen = %w[udp://127.0.0.1:0 tls://127.0.0.1:0 quic://127.0.0.1:0].map { Dohyo::Server::Listen.parse(it) }

    Sync do |task|
      server = Dohyo::Server.new(zone: fixture_zone, listen:, udp_payload_size: 1232, max_connections: 16, idle_timeout: 10, tls:)
      server.start(task)
      yield server, server.bound_addresses.to_h { |transport, address| [transport, address] }
    ensure
      server&.stop
    end
  end

  def client_environment = {"SSL_CERT_FILE" => @certificates.ca}

  # q asks one name per run, every type on one connection: one run for the apex, one for case 28.
  def assert_q(server, transport, server_url, *options)
    reference = server.bound_addresses.find { |t, _| t == "udp" }.last

    QUESTIONS.group_by { |_, (name, _)| name }.each do |name, rows|
      types = rows.map { |_, (_, type_class)| type_class::TypeValue }
      opened = server.metrics.value("dohyo_connections_opened_total", transport:).to_i
      run = q(server_url, name, types, *options)
      assert_equal opened + 1, server.metrics.value("dohyo_connections_opened_total", transport:), "#{transport} #{name}: one connection"

      # q sends the queries of a run together, and DoQ replies come back as their streams finish, in any order.
      replies = run.fetch("replies").to_h { [it.dig("question", 0, "qtype"), it] }
      assert_equal types.sort, replies.keys.sort, "#{transport} #{name}: one reply per query"
      if transport == "dot"
        run.fetch("queries").each do |query|
          assert_equal query.fetch("id"), replies.fetch(query.dig("question", 0, "qtype")).fetch("id"), "dot: the reply carries the query's ID"
        end
      end

      rows.each do |id, (_, type_class)|
        expected = Resolv::DNS::Message.decode(udp_exchange(reference, query_bytes(name, type_class, edns: 1232)))
        assert_equal summary(expected), q_summary(replies.fetch(type_class::TypeValue)), "case #{id} over #{transport}"
      end
    end
  end

  def q(server_url, name, types, *options)
    command = ["q", "@#{server_url}", *types.flat_map { ["--type", it.to_s] }, "--qname", name, "--format=json", "--timeout=5s", *options]
    # q blocks, so it runs in a thread while the reactor keeps serving.
    output, errors, status = Thread.new { Open3.capture3(client_environment, *command) }.value
    flunk "q failed:\n#{errors}" unless status.success?

    runs = JSON.parse(output)
    assert_equal 1, runs.size
    runs.first
  end

  # What is compared between q's JSON and a decoded response: the RCODE, AA, and the answer and authority RRs with
  # their TTL and the data of the fixture's types. Not RDLENGTH, which name compression changes.
  def summary(message)
    rrs = ->(section) { section.map { |name, ttl, record| ["#{name}.".downcase, record.class::TypeValue, ttl, record_data(record)] }.sort }
    {rcode: message.rcode, aa: message.aa == 1, answer: rrs.call(message.answer), authority: rrs.call(message.authority)}
  end

  def q_summary(reply)
    rrs = ->(section) { (section || []).map { [it.dig("hdr", "name").downcase, it.dig("hdr", "rrtype"), it.dig("hdr", "ttl"), q_data(it)] }.sort }
    {rcode: reply.fetch("rcode"), aa: reply.fetch("authoritative"), answer: rrs.call(reply["answer"]), authority: rrs.call(reply["ns"])}
  end

  def record_data(record)
    case record
    when IN::A, IN::AAAA then record.address.to_s.downcase
    when IN::SOA then ["#{record.mname}.", "#{record.rname}.", record.serial, record.refresh, record.retry, record.expire, record.minimum]
    when IN::HTTPS then [record.priority, record.target.to_s + ".", record.params.to_a.flat_map { it.respond_to?(:protocol_ids) ? it.protocol_ids : [] }]
    end
  end

  def q_data(rr)
    case rr.dig("hdr", "rrtype")
    when 1 then rr.fetch("a")
    when 28 then rr.fetch("aaaa")
    when 6 then rr.values_at("ns", "mbox", "serial", "refresh", "retry", "expire", "minttl")
    when 65 then [rr.fetch("priority"), rr.fetch("target"), rr.fetch("value").flat_map { it.fetch("alpn", []) }]
    end
  end

  def udp_exchange(address, bytes)
    socket = Socket.new(:INET, :DGRAM)
    socket.send(bytes, 0, Addrinfo.udp(address.ip_address, address.ip_port))
    flunk "no answer from #{address.inspect_sockaddr}" unless socket.wait_readable(5)
    socket.recv(65535)
  ensure
    socket&.close
  end

  def without_aa(bytes)
    flags = bytes.unpack1("x2n") & ~AA
    bytes.byteslice(0, 2) + [flags].pack("n") + bytes.byteslice(4..)
  end

  # dnsproxy listens on UDP and forwards every query to the upstream; it is ready once it answers through it.
  def with_dnsproxy(upstream)
    address = Addrinfo.udp("127.0.0.1", FreePort.pick)
    log = File.join(@certificates.directory, "dnsproxy.log")
    pid = Process.spawn(client_environment, "dnsproxy", "-l", address.ip_address, "-p", address.ip_port.to_s, "-u", upstream, out: log, err: [:child, :out])
    wait_for_dnsproxy(address, pid, log)
    yield address
  ensure
    if pid
      Process.kill(:TERM, pid)
      Process.wait(pid)
    end
  end

  def wait_for_dnsproxy(address, pid, log)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + READY_TIMEOUT
    probe = query_bytes(ORIGIN, IN::SOA, edns: 1232)

    loop do
      flunk "dnsproxy exited:\n#{File.read(log)}" if Process.wait(pid, Process::WNOHANG)

      socket = Socket.new(:INET, :DGRAM)
      begin
        socket.send(probe, 0, address)
        return if socket.wait_readable(0.2)
      ensure
        socket.close
      end
      flunk "dnsproxy did not answer within #{READY_TIMEOUT} seconds:\n#{File.read(log)}" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
    end
  end
end
