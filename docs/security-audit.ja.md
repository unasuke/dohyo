# セキュリティ監査

2026-09-29 時点の dohyo 0.1.0 を、ソースの読み取りで監査した結果です。

外部からゾーンを書き換えたり、再帰問い合わせの踏み台にしたりする欠陥は見当たりません。例示の設定のまま外に出すと、`/metrics` への認証前の接続だけで、TCP と DNS over TLS の受け付けを再起動まで止められます。DNS over QUIC も、ハンドシェイク前の接続で、接続の上限と無関係にメモリと CPU を使わせられます。

## 結論

| 重大度 | 件名 |
| --- | --- |
| Medium | DoQ の接続上限が、ハンドシェイク完了後にしか効かない |
| Medium | `/metrics` に接続数の上限がなく、認証より前にヘッダを全部読む |
| Medium | `/metrics` で ALPN に `h2` だけを示すと、ソケットが閉じられない |
| Low | TLS 秘密鍵のファイルモードを見ていない |
| Low | トークンの長さも、401 の回数も制限していない |
| Low | `CAP_NET_BIND_SERVICE` を起動後も持ち続ける |
| Low | ドットを含むラベルで、ゾーン外の名前に AA を付けることがある |
| 情報 | UDP の応答レート制限はない。増幅はゾーンと EDNS の上限までに収まる |
| 情報 | ループバックだけの `/metrics` は平文かつ認証なし |
| 情報 | 証明書の期限は起動時だけ見る |

先に手を入れるなら、DoQ のハンドシェイク前の接続数と、`/metrics` の同時接続数と ALPN の扱いです。

## 範囲と方法

読んだものは次のとおりです。

- `lib/dohyo/` のサーバ、ハンドラ、エンジン、応答、ゾーン、ローダ、EDNS、設定、CLI、TLS、bearer token、メトリクス、DoQ
- `examples/dohyo.yml`、`examples/dohyo.service`、`docs/operations.md`
- 依存のうち、メトリクスの入口になる `protocol-http1` 0.41.0 と `async-http` 0.105.0 のリクエスト読み取り、`openssl` 4.0.2 の `OpenSSL.secure_compare` と ALPN のコールバックの扱い、`dns-zonefile` 1.3.0 に `$INCLUDE` が無いこと、Ruby 4.0.7 の `resolv` の名前展開、`IPAddr#loopback?` の判定、`protocol-quic` のフォークが接続を作る処理と、ngtcp2 と picotls に渡す設定

`/metrics` は、ループバックで `MetricsServer` を動かし、ヘッダ、ボディ、ファイルディスクリプタの扱いを確かめました。外部からの攻撃試験、テストスイートの実行、ngtcp2 と picotls の中の処理は範囲外です。DoQ については、dohyo 側の接続受付、Ruby から見えるコールバック、フォークの設定までを見ています。DoQ の 0-RTT は、2026-09-30 に aioquic 1.3.0 のクライアントで確かめました。

重大度は次の意味です。

| 重大度 | 意味 |
| --- | --- |
| Critical | 認証なしで遠隔から、システム全体の掌握や大規模な情報漏えいにつながる |
| High | 低い手間で、大きな情報漏えいか権限昇格につながる |
| Medium | 条件は付くが、可用性を含めて実害がある |
| Low | 悪用に条件が多く、影響が小さい |
| 情報 | 欠陥というより、残るリスクと運用上の注意 |

## 発見

### DoQ の接続上限が、ハンドシェイク完了後にしか効かない

重大度は Medium です。`quic://` を待ち受けているときが対象です。例の設定は待ち受けます。

TCP と DNS over TLS は、受理の直後、TLS より前に、共有の `connection.max_connections`（既定 256）で切ります。超過した接続は、ハンドシェイクの前に閉じます。

DoQ は逆です。新しい接続では、先に接続オブジェクトとファイバを 2 本作り、`@connections` に入れ、メトリクスの接続開始を数えます。上限を見る `admit` は、`handshake_completed` のあとです。

```152:163:lib/dohyo/doq.rb
      def connection_created(connection)
        connection.listener = self
        connection.events = Thread::Queue.new
        connection.opened_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        connection.queries = 0
        @connections << connection
        @metrics.connection_opened(transport: TRANSPORT)

        # Both start at once and wait almost immediately, so they return here before the packet is processed.
        @task.async(transient: true) { serve(connection) }
        @task.async(transient: true) { connection.run }
      end
```

```212:220:lib/dohyo/doq.rb
      def admit(connection)
        if @stopping
          close_connection(connection, NO_ERROR, "shutdown")
        elsif @limiter.acquire
          connection.counted = true
        else
          close_connection(connection, EXCESSIVE_LOAD, "limit")
        end
      end
```

ハンドシェイクが終わらない接続はカウンタに入りません。ハンドシェイク専用のタイムアウトは設定していないので、アイドルタイムアウト（既定 10 秒）まで残ります。中身のない Initial はすぐ捨てられますが、ClientHello を含む Initial を大量に送ると、メモリとハンドシェイクの CPU を、設定した上限と無関係に使えます。UDP、TCP、DoT も同じプロセスなので、DoQ だけの停止では終わりません。

`protocol-quic` のフォークは Retry を送りません。`Dispatcher.cpp` には `TODO: Stateless retry.` が残っていて、送信元アドレスを確かめないまま接続を作ります。送信元を偽った Initial でも接続は残ります。偽られた相手への応答は、ngtcp2 既定の 3 倍の増幅上限に収まります。

上限超過で `DOQ_EXCESSIVE_LOAD` を返したあとも、キューに入ったクエリは `answer` が処理します。受理済みかどうかの確認がありません。

```195:208:lib/dohyo/doq.rb
      def serve(connection)
        while (event = connection.events.pop)
          kind, argument = event

          case kind
          when :handshake then admit(connection)
          when :query then answer(connection, argument)
          when :cancelled then argument.abort(REQUEST_CANCELLED)
          when :protocol_error then protocol_error(connection, argument)
          end

          connection.send_packets unless connection.disconnected?
        end
      end
```

サーバは 0-RTT も受け付けます。ngtcp2 の `ngtcp2_crypto_picotls_configure_server_context` が picotls の `max_early_data_size` を `UINT32_MAX` にし、フォークはそのままセッションチケットを発行します。2026-09-30 に aioquic 1.3.0 で確かめました。1 本目で受け取ったチケットで 2 本目を再開し、ハンドシェイクを待たずにクエリを送ると、early data が受け付けられて応答が返りました。サーバでは `:query` が `:handshake` より先に届き、`admit` より前に `answer` が走っていました。

対処するなら、ハンドシェイクの前に本数を制限し、受理していない接続では `answer` を呼ばないようにします。Retry で送信元を確かめれば、偽った送信元からの接続は残らなくなります。

### `/metrics` に接続数の上限がなく、認証より前にヘッダを全部読む

重大度は Medium です。`metrics` を有効にし、ループバック以外で待ち受けるときが対象です。例は `0.0.0.0:9153` と `[::]:9153` です。

ループバック以外では HTTPS と bearer token が必須です。トークンがないリクエストは 401 になり、ボディもパスもメソッドも区別しません。トークンはログに出ません。比較は全トークンに対する `OpenSSL.secure_compare` で、長さが違っても例外にはなりません（openssl 4.0.2 は SHA-256 で長さを隠してから固定長比較します）。この認証の形自体は妥当です。

足りないのは、認証に到達する前の資源です。`MetricsServer` は DNS 側の `ConnectionLimiter` を渡していません。

```44:52:lib/dohyo/metrics_server.rb
    def start(parent = Async::Task.current)
      @listen.each do |listen|
        endpoint = IO::Endpoint.tcp(listen.host, listen.port, wrapper: @wrapper)
        endpoint = IO::Endpoint::SSLEndpoint.new(endpoint, ssl_context: @tls_context) if @tls_context

        endpoint.bind.each do |socket|
          task = parent.async(transient: true) do
            @wrapper.accept(socket, timeout: IDLE_TIMEOUT, transport: "metrics") { |peer, address| @http.accept(peer, address) }
          end
```

トークンの検査は、HTTP 実装がリクエスト行とヘッダを読み終わったあとです。`protocol-http1` 0.41.0 は 8192 バイトを超える行を `LineLengthError` で拒否しますが、`read_headers` には行数の上限も合計サイズの上限もありません。読んだヘッダはすべてメモリに溜まります。

`IDLE_TIMEOUT` の 60 秒は、接続全体の期限ではなく、読み取り 1 回ごとの待ち時間（`IO#timeout`）です。トークンを知らない相手でも、60 秒より短い間隔でヘッダを送り続ければ、接続をいつまでも保持できます。TLS のハンドシェイクも同じ待ち時間で動くので、ClientHello を少しずつ送れば、ハンドシェイクを終えないまま保持できます。

ファイルディスクリプタとメモリは DNS と共通です。`Server::Wrapper#accept` が捕捉するのは `IOError` と `EBADF` だけです。ディスクリプタが尽きて accept が `EMFILE` を上げると、その待ち受けのタスクが終わります。尽きている間に接続が来た TCP と DoT の待ち受けも同じように終わり、ディスクリプタが空いても戻りません。プロセスは動き続けるので、systemd の `Restart=on-failure` も効きません。例の unit は `LimitNOFILE` を指定していないので、上限は systemd 既定のソフトリミット 1024 本です。

ボディは宣言された長さを一度に確保はしません。ただし keep-alive の接続では、401 を返したあとも未読のボディを最後まで読み捨ててから、次のリクエストを待ちます。大きな `Content-Length` を宣言して少しずつ送れば、ボディでも接続を保持できます。

対処するなら、`/metrics` にも同時接続の上限を付け、ヘッダの合計サイズと、リクエストを読み終えるまでの時間を、認証より前に制限します。accept が `EMFILE` を上げても、待ち受けを続けるようにします。

### `/metrics` で ALPN に `h2` だけを示すと、ソケットが閉じられない

重大度は Medium です。`metrics` を有効にし、ループバック以外で待ち受けるときが対象です。

`/metrics` の TLS コンテキストは、ALPN に `http/1.1` だけを持ち、コールバックで共通のプロトコルを選びます。

```55:58:lib/dohyo/tls.rb
      if alpn
        context.alpn_protocols = alpn
        context.alpn_select_cb = ->(offered) { (alpn & offered).first }
      end
```

クライアントが `h2` だけを示すと、コールバックは `nil` を返します。openssl 4.0.2 は戻り値を `StringValue` で文字列にしようとして `TypeError` を上げ、ハンドシェイクを fatal alert で終えてから、その例外を `accept` から上げ直します。ハンドシェイクの失敗を捕まえるのは次の `rescue` だけなので、`TypeError` は接続のタスクの外へ抜け、ソケットは GC まで閉じられません。

```109:119:lib/dohyo/server.rb
      def accept_connection(socket, address, transport:, metrics:)
        if socket.respond_to?(:start)
          begin
            socket.start
          rescue OpenSSL::SSL::SSLError, IOError, SystemCallError => error
            Console.debug(self, "connection.handshake_failed", error:)
            socket.close
            metrics&.connection_closed(transport:, reason: "error")
            return
          end
        end
```

認証の前で、接続を保持し続ける必要もありません。ループバックで 50 回試すと、サーバ側のファイルディスクリプタが 50 本残りました。上の節のとおり、ディスクリプタが尽きると TCP と DoT の待ち受けが再起動まで止まります。DoT の TLS コンテキストは ALPN を設定しないので、この経路はありません。

対処するなら、共通のプロトコルが無いときはコールバックで `OpenSSL::SSL::SSLError` を上げ、ハンドシェイクで想定外の例外が出てもソケットを閉じます。

### TLS 秘密鍵のファイルモードを見ていない

重大度は Low です。

メトリクストークンのファイルは、group と other の読み取りビットが立っていると起動を拒否します。`TLS.load` は、証明書と鍵が対応することと、起動時の有効期限だけを見ます。モードが `0644` の鍵でも起動します。運用手順は `install -m 0600` を案内しています。コード側はトークンと同じ検査がありません。

### トークンの長さも、401 の回数も制限していない

重大度は Low です。

空行は無視しますが、最短の長さはありません。1 文字のトークンでも起動します。401 に回数の制限はありません。運用手順の `openssl rand -hex 32` に従えば、オンラインでの推測は現実的ではありません。短いトークンを置いたときだけ、露出した `/metrics` を試行できます。

### `CAP_NET_BIND_SERVICE` を起動後も持ち続ける

重大度は Low です。

`examples/dohyo.service` は `User=dohyo`、`NoNewPrivileges=true`、`ProtectSystem=strict`、`ProtectHome=true`、`PrivateTmp=true` で、root では動かしません。53 番と 853 番は `AmbientCapabilities=CAP_NET_BIND_SERVICE` で bind します。バインドのあとで capability を落とさないので、プロセスを取られると、1024 未満の別のポートを改めて bind できます。

### ドットを含むラベルで、ゾーン外の名前に AA を付けることがある

重大度は Low です。想定している `sub.example.com.` のような複数ラベルの origin でも起きます。

`Zone#contains?` は、ラベル内の `.` と `\` をエスケープしたキーに対して、設定 origin の文字列が末尾に合うかで権威を判定します。

```77:79:lib/dohyo/zone.rb
    def contains?(name)
      name == @origin || name.end_with?(".#{@origin}")
    end
```

エスケープした `\.` の `.` も、`end_with?` から見るとラベルの区切りと区別がつきません。origin が `sub.example.com.` のとき、ラベル `x.sub`、`example`、`com` の 3 つからなる名前は `example.com.` の直下にあり、このゾーンの外です。そのキー `x\.sub.example.com.` は `.sub.example.com.` で終わるので、ゾーン内になります。ラベルの末尾が origin の先頭のラベルと一致すれば、origin のラベル数によらず起きます。origin が `com.` なら、ラベル 1 個の名前 `x.com`（通常の 2 ラベルの `x.com.` とは別の名前）も同じです。

ゾーンのキーにはエスケープしたドットが現れないので、こうした名前はどれも存在しない名前として扱われ、AA の NXDOMAIN になります。正の回答や NODATA にはなりません。キャッシュのキーは問い合わせた名前そのものなので、通常の `x.sub.example.com.` の回答にもなりません。

ラベルが origin 全体を含むだけなら、ゾーン外のままです。ラベル 1 個の `www.sub.example.com` のキーは `www\.sub\.example\.com.` で、`.sub.example.com.` では終わりません。`example.com.`、`notexample.com.`、`www.example.com.` も、`sub.example.com.` に対してゾーン外のままでした。

## 残るリスク

UDP の応答レート制限はありません。再帰は無く、ゾーン外は `REFUSED`、`ANY` は RRset 1 つ、追加セクションにグルーを足すこともありません。UDP の既定上限は 1232 バイト、設定の最大は 4096 バイトです。増幅は、ゾーンに置いたレコードとこの上限までに収まります。偽装した送信元への反射は、権威サーバとして残ります。

TCP、DoT、DoQ で共有する接続の上限（既定 256）は、送信元ごとではありません。1 つの送信元が、アイドルタイムアウトより短い間隔で問い合わせを送る接続を上限の数だけ保てば、ほかのクライアントは TCP、DoT、DoQ で答えを受け取れません。UDP は影響を受けません。

ループバックだけの `/metrics` は平文で、認証もありません。`bearer_token_file` を書いても、listen がすべてループバックならトークンは使いません。`127.0.0.0/8`、`::1`、`::ffff:127.0.0.1` をループバックとみなします（Ruby 4.0.7 の `IPAddr` で確認）。共有ホストや、SSH で転送したポートからは、そのまま読めます。中身はクエリ名ではなく、RCODE やトランスポートごとの回数、SOA シリアル、dohyo と Ruby のバージョンです。

証明書と秘密鍵は起動時に読み、`SIGHUP` では読み直しません。有効期限も起動時だけです。期限切れのあとも、再起動までは同じ証明書で待ち受けます。運用文書と一致しています。

## 確認して問題なしとした箇所

権威の境界です。再帰は実装していません。応答の `RA` は 0 です。QUERY 以外の opcode は `NOTIMP`、クラスが IN でない問い合わせと AXFR（252）/ IXFR（251）は `REFUSED`、`QR=1` には応答しません。権威外の名前は `REFUSED` で、AA は立てません。

入力の受け取りです。設定は `YAML.safe_load` で、エイリアスも未知のキーも拒否します。ゾーンファイルは SOA、NS、A、AAAA、HTTPS 以外を拒否し、頂点以外の NS とワイルドカードも拒否します。dns-zonefile 1.3.0 に `$INCLUDE` はありません。EDNS のオプションはエコーせず、UDP サイズは 512 から設定値の間に丸めます。`resolv` の名前展開は、前向きの圧縮ポインタと 255 オクテットを超える名前を拒否します。

トランスポートです。DoT と `/metrics` の TLS は 1.3 のみ、圧縮なし、クライアント証明書なしです。IPv6 の待ち受けは `IPV6_V6ONLY` で、`[::]` が IPv4 射影アドレスを受けません。TCP と DoT には読み取りごとのアイドルタイムアウトがあり、接続上限はハンドシェイクより前です。DoQ は、ストリームあたりクエリ 1 つ、メッセージ ID 0、`edns-tcp-keepalive` の拒否、片方向ストリーム 0、接続あたりの双方向ストリーム上限を持っています。

メトリクスとゾーンの差し替えです。系列のラベルは決まった集合だけで、クライアントの入力では増えません。ラベルの `\`, `"`, 改行はエスケープします。露出した待ち受けでは、認証がパスとメソッドより先です。トークンファイルのモード、比較、ログからの除外はテストにあります。ゾーンの差し替えは参照の置き換えで、処理中のクエリは開始時のゾーンを最後まで使います。同じシリアルで中身だけが変わった再読込は拒否します。

## 監査の限界

外部から実行中のプロセスにパケットを送る試験はしていません。上の「確認した」は、コードと、ループバック判定などの小さな実行です。サーバを動かしたのは、ループバックでの `/metrics` と TCP、DoQ の 0-RTT の確認だけです。QUIC の Retry と増幅上限は、フォークが ngtcp2 と picotls に渡す設定までを読みました。ngtcp2 と picotls の中の処理は追っていません。DoQ をインターネットに出す前に、そこは別途見る必要があります。
