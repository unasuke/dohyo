# 運用

dohyo の導入、起動、更新、確認の手順です。例では、ネームサーバを `ns.example.com`、それが答えるゾーンを `sub.example.com`（`example.com` から委任される）としています。dohyo が何をどう答えるかは設計の文書で扱い、ここでは書きません。

## 導入

dohyo は gem としては入れず、git のチェックアウトを Bundler で動かします。

Debian 13 でのビルドに要るパッケージは次のとおりです。

```sh
sudo apt-get install -y --no-install-recommends git curl ca-certificates build-essential \
  libssl-dev libyaml-dev zlib1g-dev libffi-dev pkg-config cmake clang libzstd-dev
```

1 行目と、`libssl-dev`・`libyaml-dev`・`zlib1g-dev`・`libffi-dev` は Ruby のビルドに使います。protocol-quic（DNS over QUIC）は、g++ ではなく `clang++` と `cmake` でビルドします。そのビルドの道具が依存する rugged は OpenSSL を静的にリンクするので、Debian では `libzstd-dev` が、最近の Ubuntu ではさらに `libjitterentropy3-dev` が要ります。下の確認に使う kdig は `knot-dnsutils` に入っています。

小さなインスタンスでは、ビルドの間だけ swap を足してください。1 つずつビルドするならプロセスは小さいのですが、CPU が複数あると Ruby も protocol-quic も並列にコンパイルします。

Ruby 4.0.7 は、[ruby-build](https://github.com/rbenv/ruby-build) で `/usr/local` の下に入れます。

```sh
git clone https://github.com/rbenv/ruby-build /tmp/ruby-build
sudo /tmp/ruby-build/install.sh
sudo TMPDIR=/var/tmp ruby-build 4.0.7 /usr/local/ruby-4.0.7
```

Debian 13 は `/tmp` をメモリの半分の大きさの tmpfs としてマウントするので、小さなインスタンスでは Ruby のビルドに足りません。`TMPDIR=/var/tmp` で、ディスク上でビルドします。

dohyo は設定とゾーンをロケールによらず UTF-8 として読むので、最小構成の C ロケールのままで構いません。

あとで Ruby を上げるときは、新しい版を隣のディレクトリに入れ、systemd のユニットのパスを書き換えます。

実行用のユーザーを作り、dohyo をチェックアウトします。

```sh
sudo useradd --system --home-dir /opt/dohyo --shell /usr/sbin/nologin dohyo
sudo git clone https://github.com/unasuke/dohyo /opt/dohyo
sudo chown -R dohyo:dohyo /opt/dohyo
cd /opt/dohyo
sudo -u dohyo /usr/local/ruby-4.0.7/bin/bundle config set --local deployment true
sudo -u dohyo /usr/local/ruby-4.0.7/bin/bundle config set --local without development
sudo -u dohyo /usr/local/ruby-4.0.7/bin/bundle install
```

DNS over QUIC には、Gemfile が参照している [unasuke/protocol-quic](https://github.com/unasuke/protocol-quic) の `ruby-stream-io-bindings` ブランチが要ります。`bundle install` がビルドします。`quic://` の待ち受けが無ければ、dohyo はこれを読み込みません。

## 設定

設定は [`examples/dohyo.yml`](../examples/dohyo.yml) をもとに `/etc/dohyo/dohyo.yml` に置き、ゾーンはそこで指定したファイルに置きます（[zone-file.ja.md](zone-file.ja.md) を参照）。知らない鍵はエラーになります。

サーバを起動せずに、すべてを検査できます。

```sh
sudo -u dohyo /usr/local/ruby-4.0.7/bin/bundle exec exe/dohyo --config /etc/dohyo/dohyo.yml --check
```

設定、ゾーン、証明書、メトリクスのトークンファイルを読み込み、ゾーンの原点とシリアル、トークンの本数を出します（トークンそのものは出しません）。終了コードは、成功で 0、どれかが不正なら 1、引数の誤りなら 2 です。

## systemd で動かす

[`examples/dohyo.service`](../examples/dohyo.service) を `/etc/systemd/system/dohyo.service` として置きます。

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now dohyo
```

このユニットは、起動の前に `--check` を実行し、`dohyo` ユーザーで動きます。53 番と 853 番のポートは、root ではなく `AmbientCapabilities=CAP_NET_BIND_SERVICE` で bind します。

- `systemctl reload dohyo` は `SIGHUP` を送ります。ゾーンとメトリクスのトークンファイルを読み直します。証明書は読み直しません。
- `systemctl stop dohyo` は `SIGTERM` を送ります。dohyo は新しい受け付けを止め、処理中の問い合わせに最大 5 秒かけて答え、DoQ の接続を DOQ_NO_ERROR で閉じてから、終了コード 0 で終わります。

## ログ

dohyo は標準エラーにログを出し、journald がそれを集めます。

```sh
journalctl -u dohyo -f
```

systemd の下では 1 件ずつ 1 行の JSON で、端末ならテキストで出ます。形式は `CONSOLE_OUTPUT` で変えられます。`CONSOLE_LEVEL=debug` にすると、問い合わせを 1 件ずつログに出します（名前と型だけで、相手のアドレスは出しません）。

## ゾーンを変える

1. ゾーンファイルを書き換え、SOA のシリアルを上げます。
2. 検査します：`bundle exec exe/dohyo --config /etc/dohyo/dohyo.yml --check`
3. `sudo systemctl reload dohyo`

再読み込みに失敗したときは、それまでのゾーンで答え続けます。成功したか失敗したかは、ログ（`zone.reloaded`、または理由つきの `zone.load_failed`）か、メトリクス（`dohyo_zone_serial`、`dohyo_zone_reloads_total{result="failure"}`）で見分けます。シリアルが同じまま中身が変わっていたら、わざと拒否します。シリアルの上げ忘れに気づけるようにするためです。

## dohyo を更新する

```sh
cd /opt/dohyo
sudo -u dohyo git pull
sudo -u dohyo /usr/local/ruby-4.0.7/bin/bundle install
sudo -u dohyo /usr/local/ruby-4.0.7/bin/bundle exec exe/dohyo --config /etc/dohyo/dohyo.yml --check && sudo systemctl restart dohyo
```

`--check` が失敗したら、再起動しないでください。

## 証明書

DoT、DoQ、`/metrics` の HTTPS は、ネームサーバの名前（`ns.example.com`）の証明書 1 つを共有します。Let's Encrypt なら、その名前がある親ゾーンで DNS-01 の認証ができるので、dohyo が答えるゾーンに TXT レコードは要りません。たとえば Route 53 なら、certbot の `dns-route53` プラグインを使います。

Let's Encrypt のファイルは root しか読めません。dohyo は証明書を起動時にしか読まないので、deploy hook で dohyo 用に写してから再起動します。たとえば `/etc/letsencrypt/renewal-hooks/deploy/dohyo` を次のようにします。

```sh
#!/bin/sh
set -e
install -o dohyo -g dohyo -m 0600 "$RENEWED_LINEAGE/fullchain.pem" /etc/dohyo/tls/fullchain.pem
install -o dohyo -g dohyo -m 0600 "$RENEWED_LINEAGE/privkey.pem" /etc/dohyo/tls/privkey.pem
systemctl restart dohyo
```

再起動の間の数秒は応答が止まりますが、リゾルバが再送します。

## メトリクス

設定に `metrics` の節があれば、dohyo は Prometheus 向けのメトリクスを `/metrics` で出します。ループバックだけで待ち受けるなら平文の HTTP です。それ以外では上の証明書を使った HTTPS になり、すべてのリクエストに Bearer トークンが要ります。

トークンファイルを、`dohyo` だけが読めるように作ります。

```sh
sudo install -d -o root -g dohyo -m 0750 /etc/dohyo/secrets
openssl rand -hex 32 | sudo tee /etc/dohyo/secrets/metrics-tokens >/dev/null
sudo chown dohyo:dohyo /etc/dohyo/secrets/metrics-tokens
sudo chmod 0600 /etc/dohyo/secrets/metrics-tokens
```

このファイルがグループや他人から読める、またはトークンが 1 つも無いと、dohyo は起動しません。

Prometheus の設定は次のとおりです。

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

scrape を失敗させずにトークンを入れ替える手順です。

1. 新しいトークンをトークンファイルの 2 行目に足し、`systemctl reload dohyo` します。この時点で両方のトークンが有効です。
2. Prometheus の credentials のファイルを新しいトークンに書き換えます。
3. 古いトークンの行を消し、もう一度 `systemctl reload dohyo` します。

再読み込みのときにトークンファイルが読めない、または空なら、それまでのトークンを使い続けます（ログは `metrics.tokens_reload_failed`）。

見ておくとよいクエリの例です。

```text
# 暗号化された問い合わせの割合
sum(rate(dohyo_queries_total{transport=~"dot|doq"}[5m])) / sum(rate(dohyo_queries_total[5m]))

# RCODE ごとの内訳
sum by (rcode) (rate(dohyo_queries_total[5m]))

# UDP で切り詰めた応答の割合
rate(dohyo_responses_truncated_total[5m]) / sum(rate(dohyo_queries_total{transport="udp"}[5m]))
```

## ゾーンを委任する

親ゾーン（`example.com`）に次のレコードを置きます。

```text
sub.example.com.      3600   IN NS    ns.example.com.
ns.example.com.       86400  IN A     192.0.2.53
ns.example.com.       86400  IN AAAA  2001:db8::53
_dns.ns.example.com.  3600   IN SVCB  1 . alpn=dot
```

dohyo が答えるゾーンの頂点の NS も、同じサーバの名前にします。`_dns` の SVCB レコード（RFC 9461）は、暗号化したトランスポートに対応していることを告知します。実際に動いているものだけを書き、`doq` は DoQ が安定して動いてから足します。DoT や DoQ を止めるときは、先に SVCB から外し、その TTL が切れてから待ち受けを止めます。

### ゾーンを dohyo に移す

その名前の A、AAAA、HTTPS のレコードがすでに親ゾーンにあると、NS レコードとは共存できません。そのため、切り替えはそれらを置き換える作業になります。

1. 同じレコードを dohyo で答えるようにし、dohyo に直接問い合わせて確かめます（下を参照）。
2. 親ゾーンにあるそれらのレコードの TTL を 300 秒に下げ、元の TTL が切れるまで待ちます。
3. 親ゾーンへの 1 回の変更で、それらのレコードを消し、TTL 300 秒の NS レコードを足します。
4. 公開のリゾルバ経由で答えを確かめます。
5. `_dns` の SVCB レコードを足します。すべて安定したら、NS の TTL を 3600 に上げます。

切り戻すときは、親ゾーンの NS レコードを消し、元のレコードを戻します。TTL を短くしてあるので、すぐに効きます。

## サーバを確かめる

[kdig](https://www.knot-dns.cz/)（knot-dnsutils）で確かめます。

```sh
kdig @ns.example.com sub.example.com SOA           # UDP
kdig @ns.example.com sub.example.com A +tcp        # TCP
kdig @ns.example.com sub.example.com AAAA +tls     # DNS over TLS
kdig @ns.example.com sub.example.com HTTPS +quic   # DNS over QUIC

# リゾルバ経由で、委任と告知を確かめる
kdig sub.example.com NS
kdig _dns.ns.example.com SVCB
```
