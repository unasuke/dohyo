# Writing the zone file

dohyo serves one zone from one BIND-format zone file. It is read at startup, by `dohyo --check`, and again on `SIGHUP`. If any check below fails, the file is rejected as a whole: at startup dohyo refuses to start, and on reload it keeps serving the zone it already has.

See [`examples/sub.example.com.zone`](../examples/sub.example.com.zone) for a complete file.

## Record types

Only these types are accepted:

| Type | Where | Notes |
| --- | --- | --- |
| SOA | the apex only | exactly one in the whole file |
| NS | the apex only | at least one; the same names as the delegation in the parent zone |
| A | any name | |
| AAAA | any name | |
| HTTPS | any name | see below |

Any other type (CNAME, MX, TXT, CAA, …) is an error. So are NS records below the apex (delegations) and wildcard names (`*.sub.example.com.`).

Queries for other types at an existing name get an empty answer (NODATA); queries for names that do not exist get NXDOMAIN. Names that only exist because something lies below them (for example `y` when only `x.y` has records) are treated as existing.

## Directives

- `$ORIGIN` is required and must be the configured `zone.origin`. Without it, relative names would be resolved against the root. Names written before the first `$ORIGIN` end up outside the zone and are rejected.
- `$TTL` takes a number of seconds only (`$TTL 3600`, not `$TTL 1h`). The parser dohyo uses reads `$TTL 1h` as 1 second, so units are refused there. Units in a record's own TTL field (`www 1h IN A …`) work.
- Any other directive, such as `$INCLUDE` or `$GENERATE`, is refused. The parser dohyo uses would skip `$INCLUDE` without reading the file, and its records would be missing without a word.

## TTLs

TTLs must be between 0 and 2147483647 seconds. When the records of one name and type have different TTLs, the smallest is used for all of them and a warning is logged.

Negative answers (NODATA and NXDOMAIN) are cached for the smaller of the SOA's own TTL and its MINIMUM field.

## HTTPS records

Both ServiceMode (priority 1 or more) and AliasMode (priority 0) are accepted, and a name may have several HTTPS records. These SvcParam keys are understood:

| Key | Value | Example |
| --- | --- | --- |
| `mandatory` | comma-separated key names | `mandatory=alpn,port` |
| `alpn` | comma-separated protocol IDs | `alpn=h3,h2` |
| `no-default-alpn` | no value | `no-default-alpn` |
| `port` | 0–65535 | `port=8443` |
| `ipv4hint` | comma-separated IPv4 addresses | `ipv4hint=192.0.2.1,192.0.2.2` |
| `ech` | base64 | `ech=AEX+DQ==` |
| `ipv6hint` | comma-separated IPv6 addresses | `ipv6hint=2001:db8::1` |
| `dohpath` | a URI template | `dohpath=/dns-query{?dns}` |
| `keyNNNN` | any value; a known key number uses that key's format | `key65000=opaque` |

Values may be quoted (`alpn="h3,h2"`). Backslash escapes are not supported and are rejected. Any other key name is an error.

Write each key once. A key written both by name and as `keyNNNN` (`dohpath=… key7=…`) is rejected. The same key name written twice (`port=443 port=8443`) cannot be detected: the parser keeps the last value silently.

## The serial

Raise the SOA serial on every change; the `YYYYMMDDnn` form is a good habit. On `SIGHUP`:

- a newer serial replaces the zone;
- the same serial with the same content does nothing;
- the same serial with different content, or an older serial, is refused and the old zone keeps being served.

Serials are compared with RFC 1982 serial arithmetic, so they may wrap around.

## Checking a change

```sh
dohyo --config /etc/dohyo/dohyo.yml --check
```

It prints the origin and the serial on success, or the reason for the failure, naming the file and the check that failed. Run it before `systemctl reload dohyo`.
