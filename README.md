# Dohyo

dohyo is an authoritative DNS server written in Ruby. It answers for one zone, read from a BIND-format zone file, over UDP and TCP, DNS over TLS (RFC 7858) and DNS over QUIC (RFC 9250), and exposes Prometheus metrics.

It is deliberately small: the zone may hold SOA, NS, A, AAAA and HTTPS records, and there is no recursion, DNSSEC signing, zone transfer, wildcard, CNAME or delegation below the apex.

## Installation

dohyo needs Ruby 4.0 or later and runs from a git checkout:

```bash
git clone https://github.com/unasuke/dohyo
cd dohyo
bundle install
```

DNS over QUIC uses a fork of protocol-quic ([unasuke/socketry-protocol-quic](https://github.com/unasuke/socketry-protocol-quic), branch `ruby-stream-io-bindings`), a native extension built on ngtcp2. Building it needs clang (`clang++`), cmake, pkg-config and the OpenSSL headers; on Debian 13 also `libzstd-dev`, and on Ubuntu 26.04 both `libzstd-dev` and `libjitterentropy3-dev`. Without a `quic://` listener it is never loaded.

See [docs/operations.md](docs/operations.md) for the full list of packages on Debian 13 and for installing on a server with systemd.

## Usage

A minimal configuration:

```yaml
zone:
  origin: sub.example.com.
  file: /etc/dohyo/zones/sub.example.com.zone
listen:
  - udp://0.0.0.0:53
  - tcp://0.0.0.0:53
  - tls://0.0.0.0:853
  - quic://0.0.0.0:853
tls:
  certificate_chain: /etc/dohyo/tls/fullchain.pem
  private_key: /etc/dohyo/tls/privkey.pem
```

```bash
bundle exec exe/dohyo --config /etc/dohyo/dohyo.yml --check   # validate and exit
bundle exec exe/dohyo --config /etc/dohyo/dohyo.yml           # serve
```

`SIGHUP` reloads the zone; `SIGTERM` shuts down gracefully.

- [docs/operations.md](docs/operations.md): running with systemd, reloading, certificates, metrics, delegating a zone
- [docs/zone-file.md](docs/zone-file.md): what the zone file may contain and how it is checked
- [examples/](examples/): a full configuration, a zone file and a systemd unit

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `bundle exec rake` to run the tests, standard and Steep. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

The integration tests use kdig (knot-dnsutils) when it is installed, and skip the DNS over QUIC tests when protocol-quic is not.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/unasuke/dohyo. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [code of conduct](https://github.com/unasuke/dohyo/blob/main/CODE_OF_CONDUCT.md).

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the Dohyo project's codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/unasuke/dohyo/blob/main/CODE_OF_CONDUCT.md).
