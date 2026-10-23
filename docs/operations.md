# Operations

How to install, run, update and check dohyo. The examples use `ns.example.com` as the name server and `sub.example.com` as the zone it serves, delegated from `example.com`. What dohyo answers, and why, is described in the design document, not here.

## Installing

dohyo runs from a git checkout with Bundler; it is not installed as a gem.

Build requirements, on Debian 13:

```sh
sudo apt-get install -y --no-install-recommends git curl ca-certificates build-essential \
  libssl-dev libyaml-dev zlib1g-dev libffi-dev pkg-config cmake clang libzstd-dev
```

The first line and `libssl-dev`, `libyaml-dev`, `zlib1g-dev` and `libffi-dev` build Ruby. protocol-quic (DNS over QUIC) is built with `clang++` (not g++) and `cmake`. Its build tool depends on rugged, whose build links OpenSSL statically and so needs the development packages of the libraries OpenSSL uses (`pkg-config --static --libs libcrypto` lists them): `libzstd-dev` on Debian 13, and both `libzstd-dev` and `libjitterentropy3-dev` on Ubuntu 26.04. `knot-dnsutils` provides kdig for the checks below.

On a small instance, add swap for the build; the processes are small when built one at a time, but Ruby and protocol-quic compile in parallel when there are several CPUs.

Install Ruby 4.0.7 under `/usr/local` with [ruby-build](https://github.com/rbenv/ruby-build):

```sh
git clone https://github.com/rbenv/ruby-build /tmp/ruby-build
sudo /tmp/ruby-build/install.sh
sudo TMPDIR=/var/tmp ruby-build 4.0.7 /usr/local/ruby-4.0.7
```

Debian 13 mounts `/tmp` as tmpfs, sized at half the memory, which is too small to build Ruby on a small instance; `TMPDIR=/var/tmp` builds on disk instead.

dohyo reads the configuration and the zone as UTF-8 whatever the locale, so the minimal system's C locale is fine.

To upgrade Ruby later, install the new version next to it and change the paths in the systemd unit.

Create a user for the service, and check out dohyo as the account you administer the server with (`deploy` here). The code belongs to that account and `dohyo` can only read it, so the server cannot change its own code:

```sh
sudo useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin dohyo
sudo install -d -o deploy -g deploy -m 0755 /opt/dohyo
git clone https://github.com/unasuke/dohyo /opt/dohyo
cd /opt/dohyo
/usr/local/ruby-4.0.7/bin/bundle config set --local deployment true
/usr/local/ruby-4.0.7/bin/bundle config set --local without development
/usr/local/ruby-4.0.7/bin/bundle install
```

Run `git` and `bundle` in `/opt/dohyo` as `deploy`, without sudo: git refuses to work in a repository owned by another user.

DNS over QUIC needs the `ruby-stream-io-bindings` branch of [unasuke/socketry-protocol-quic](https://github.com/unasuke/socketry-protocol-quic), which the Gemfile refers to; `bundle install` builds it. Without a `quic://` listener, dohyo does not load it.

## Configuring

Put the configuration in `/etc/dohyo/dohyo.yml`, starting from [`examples/dohyo.yml`](../examples/dohyo.yml), and the zone in the file it names (see [zone-file.md](zone-file.md)). Unknown keys are errors.

Check everything without starting the server:

```sh
sudo -u dohyo /usr/local/ruby-4.0.7/bin/bundle exec exe/dohyo --config /etc/dohyo/dohyo.yml --check
```

It runs as `dohyo`, since only `dohyo` can read the private key and the metrics token file. It loads the configuration, the zone, the certificate and the metrics token file, then prints the zone's origin and serial and the number of tokens (never the tokens). The exit status is 0 on success, 1 when something is invalid, and 2 for bad arguments.

## Running with systemd

Install [`examples/dohyo.service`](../examples/dohyo.service) as `/etc/systemd/system/dohyo.service`:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now dohyo
```

The unit runs `--check` before starting, runs as `dohyo`, and binds ports 53 and 853 through `AmbientCapabilities=CAP_NET_BIND_SERVICE` rather than as root.

- `systemctl reload dohyo` sends `SIGHUP`: the zone and the metrics token file are read again. The certificate is not.
- `systemctl stop dohyo` sends `SIGTERM`: dohyo stops accepting, answers the queries in progress for up to 5 seconds, closes DoQ connections with DOQ_NO_ERROR, and exits with status 0.

## Logs

dohyo logs to standard error, which journald collects:

```sh
journalctl -u dohyo -f
```

Under systemd each event is one line of JSON; on a terminal it is text. Set `CONSOLE_OUTPUT` to choose otherwise, and `CONSOLE_LEVEL=debug` to log every query (names and types, never client addresses).

## Changing the zone

1. Edit the zone file and raise the SOA serial.
2. Check it in `/opt/dohyo`: `sudo -u dohyo /usr/local/ruby-4.0.7/bin/bundle exec exe/dohyo --config /etc/dohyo/dohyo.yml --check`.
3. `sudo systemctl reload dohyo`.

A reload that fails keeps the previous zone. Tell success from failure in the log (`zone.reloaded` or `zone.load_failed` with the reason) or in the metrics (`dohyo_zone_serial`, `dohyo_zone_reloads_total{result="failure"}`). The same serial with different content is refused on purpose: it catches a forgotten serial bump.

## Updating dohyo

```sh
cd /opt/dohyo
git pull
/usr/local/ruby-4.0.7/bin/bundle install
sudo -u dohyo /usr/local/ruby-4.0.7/bin/bundle exec exe/dohyo --config /etc/dohyo/dohyo.yml --check && sudo systemctl restart dohyo
```

Do not restart when `--check` fails.

## The certificate

DoT, DoQ and HTTPS for `/metrics` share one certificate for the name server's name (`ns.example.com`). With Let's Encrypt, the DNS-01 challenge can be solved in the parent zone, where that name lives, so the served zone needs no TXT record; for example, with Route 53, use certbot's `dns-route53` plugin.

The Let's Encrypt files are readable by root only. Copy them for dohyo in a deploy hook and restart, since dohyo reads the certificate only at startup. For example, `/etc/letsencrypt/renewal-hooks/deploy/dohyo`:

```sh
#!/bin/sh
set -e
install -o dohyo -g dohyo -m 0600 "$RENEWED_LINEAGE/fullchain.pem" /etc/dohyo/tls/fullchain.pem
install -o dohyo -g dohyo -m 0600 "$RENEWED_LINEAGE/privkey.pem" /etc/dohyo/tls/privkey.pem
systemctl restart dohyo
```

dohyo refuses to start if the private key is readable by group or others.

A restart stops answering for a few seconds; resolvers retry.

## Metrics

With a `metrics` section, dohyo serves Prometheus metrics at `/metrics`. On loopback only it is plain HTTP. Anywhere else it is HTTPS with the certificate above, and every request needs a bearer token.

Create the token file, readable only by `dohyo`:

```sh
sudo install -d -o root -g dohyo -m 0750 /etc/dohyo/secrets
openssl rand -hex 32 | sudo tee /etc/dohyo/secrets/metrics-tokens >/dev/null
sudo chown dohyo:dohyo /etc/dohyo/secrets/metrics-tokens
sudo chmod 0600 /etc/dohyo/secrets/metrics-tokens
```

dohyo refuses to start if the file is readable by group or others, holds no token, or holds a token shorter than 32 bytes.

Prometheus:

```yaml
scrape_configs:
  - job_name: dohyo
    scheme: https
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/secrets/dohyo-metrics-token
    static_configs:
      - targets: ['ns.example.com:9153']
```

Before the token is checked, `/metrics` limits what a client can hold: 16 connections across every listen address, 10 seconds for the TLS handshake, and 10 seconds for the request line and headers, which may have up to 64 fields and 16 KiB. A request without a valid token gets 401 and its connection is closed. The limits are fixed; one Prometheus server needs one or two connections.

To replace the token without a failed scrape:

1. Add the new token as a second line of the token file and `systemctl reload dohyo`. Both tokens are valid now.
2. Put the new token in Prometheus's credentials file.
3. Remove the old line and `systemctl reload dohyo` again.

A token file that cannot be read on reload, is empty or holds a token shorter than 32 bytes keeps the previous tokens (logged as `metrics.tokens_reload_failed`).

Queries worth watching:

```text
# Share of encrypted queries
sum(rate(dohyo_queries_total{transport=~"dot|doq"}[5m])) / sum(rate(dohyo_queries_total[5m]))

# Answers by RCODE
sum by (rcode) (rate(dohyo_queries_total[5m]))

# Truncated UDP answers
rate(dohyo_responses_truncated_total[5m]) / sum(rate(dohyo_queries_total{transport="udp"}[5m]))
```

## Delegating the zone

In the parent zone (`example.com`):

```text
sub.example.com.      3600   IN NS    ns.example.com.
ns.example.com.       86400  IN A     192.0.2.53
ns.example.com.       86400  IN AAAA  2001:db8::53
_dns.ns.example.com.  3600   IN SVCB  1 . alpn=dot
```

The apex NS in the served zone must name the same servers. The `_dns` SVCB record (RFC 9461) announces the encrypted transports; list only those actually served, and add `doq` once DoQ has run reliably. When stopping DoT or DoQ, remove it from the SVCB record first and stop listening after its TTL has passed.

### Moving a zone to dohyo

When the name already has A, AAAA or HTTPS records in the parent zone, they cannot coexist with its NS records, so the switch replaces them:

1. Serve the same records from dohyo, and check them against it directly (see below).
2. Lower the TTL of the records in the parent zone to 300 seconds, and wait for the old TTL to pass.
3. In one change to the parent zone, delete those records and add the NS record, with a TTL of 300 seconds.
4. Check the answers through a public resolver.
5. Add the `_dns` SVCB record. Once everything is stable, raise the NS TTL to 3600.

To roll back, delete the NS record and restore the records in the parent zone; with the short TTL this takes effect quickly.

## Checking the server

With [kdig](https://www.knot-dns.cz/) (knot-dnsutils):

```sh
kdig @ns.example.com sub.example.com SOA           # UDP
kdig @ns.example.com sub.example.com A +tcp        # TCP
kdig @ns.example.com sub.example.com AAAA +tls     # DNS over TLS
kdig @ns.example.com sub.example.com HTTPS +quic   # DNS over QUIC

# The delegation and the announcement, through a resolver
kdig sub.example.com NS
kdig _dns.ns.example.com SVCB
```
