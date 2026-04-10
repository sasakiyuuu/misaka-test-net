# MISAKA Testnet Launcher

MISAKA testnet に初心者でも参加しやすい形で入るための配布 repo です。

## ダウンロード

| Platform | File |
|---|---|
| Windows x86_64 | [misaka-public-node-windows-x86_64.zip](https://github.com/sasakiyuuu/misaka-test-net/releases/latest/download/misaka-public-node-windows-x86_64.zip) |
| macOS arm64 | [misaka-public-node-macos-arm64.tar.gz](https://github.com/sasakiyuuu/misaka-test-net/releases/latest/download/misaka-public-node-macos-arm64.tar.gz) |
| Linux x86_64 | [misaka-public-node-linux-x86_64.tar.gz](https://github.com/sasakiyuuu/misaka-test-net/releases/latest/download/misaka-public-node-linux-x86_64.tar.gz) |
| SHA256 | [SHA256SUMS](https://github.com/sasakiyuuu/misaka-test-net/releases/latest/download/SHA256SUMS) |
| 署名 (Sigstore) | [SHA256SUMS.sig](https://github.com/sasakiyuuu/misaka-test-net/releases/latest/download/SHA256SUMS.sig) + [SHA256SUMS.pem](https://github.com/sasakiyuuu/misaka-test-net/releases/latest/download/SHA256SUMS.pem) |

最新 release 一覧: <https://github.com/sasakiyuuu/misaka-test-net/releases/latest>

## 使い方

### Windows

1. zip を展開
2. `start-public-node.bat` をダブルクリック

### macOS

1. tar.gz を展開
2. `start-public-node.command` をダブルクリック

もし macOS が「Mac に損害を与える可能性があるため開けません」などと表示した場合は、展開したフォルダに対して一度だけ quarantine を外してください。

```bash
xattr -dr com.apple.quarantine <展開したフォルダ名>
```

### Linux

1. tar.gz を展開
2. `./start-public-node.sh` を実行

## 動作確認

ノード起動後、別のターミナルで状態を確認できます:

```bash
curl http://localhost:3001/api/health
# => {"blocks":N,"round":N,"status":"ok"}

curl http://localhost:3001/api/get_chain_info
# => {"chainId":2,"version":"0.5.6","mode":"solo"|"joined","peerCount":N,...}
```

`mode` が `joined` になっていれば、共有テストネットのピアと接続している状態です。
`solo` の場合は自ノード単独で progress している状態 (seed に繋がっていない等)。

## seed の差し替え

公開 seed が変わった場合は、配布物の `config/seeds.txt` を編集してください。

- 1 行に 1 つ `HOST:PORT`
- ノード起動時に読み込まれます

公開 seed と PK-pinning 付きで接続する場合は seed ノードの
ML-DSA-65 公開鍵も必要です。`start-public-node.*` は現時点では
`seeds.txt` しか読み込まないため、pubkey 付き接続は
`misaka-node --seeds HOST:PORT --seed-pubkeys 0x<hex>` を手動で
呼ぶか、`seed-pubkeys.txt` launcher 対応 (今後追加予定) を
待ってください。

## genesis（委員会）とバンドル鍵

初回起動時、`start-public-node.*` は `config/bundled-validator.key` を
`misaka-data/validator.key` にコピーし（未作成のときのみ）、
`config/genesis_committee.toml` を `--genesis-path` で渡します。

- パッケージ同梱の genesis は **配布用の単一バリデータ委員会** です。
  公式テストネットと `genesis_hash` を一致させるには、運営が公開する
  公式 `genesis_committee.toml` に差し替えてください。
- 同梱の `bundled-validator.key` は genesis の authority 0 と対応しています。
  これは **単独 smoke テスト専用の demo key** です。
  **複数ユーザーが同一ネットワーク上で同時に同じ鍵を使うと equivocation を起こします。**
- `chain_id=1` (mainnet) では bundled key の使用を自動で拒否する
  ガードが入っています（v0.5.4 以降）。

## 含まれているもの

各プラットフォームの配布物は以下の構成です:

```
misaka-public-node-<platform>/
├── misaka-node(.exe)             # ノードバイナリ
├── start-public-node.sh          # Linux / macOS 起動スクリプト
├── start-public-node.command     # macOS 用ダブルクリック launcher (macOS only)
├── start-public-node.bat         # Windows 用ダブルクリック launcher (Windows only)
└── config/
    ├── public-node.toml          # ノード設定 (chain_id=2, ポート, 他)
    ├── genesis_committee.toml    # 起動用委員会マニフェスト
    ├── bundled-validator.key     # 初回コピー用 demo key (authority 0 対応)
    ├── seeds.txt                 # 公式 seed 接続先
    └── self-host-seeds.txt       # ローカル self-host 用 seed
```

## 検証（オプション）

リリースアセットは Sigstore cosign で keyless 署名されています。

```bash
cosign verify-blob \
  --certificate SHA256SUMS.pem \
  --signature SHA256SUMS.sig \
  --certificate-identity-regexp 'https://github\.com/sasakiyuuu/misaka-test-net/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  SHA256SUMS
```

`Verified OK` が出れば、SHA256SUMS は当該リポジトリの GitHub Actions ワークフロー
から生成されたものであることが暗号学的に保証されます。次に:

```bash
sha256sum -c SHA256SUMS 2>/dev/null || shasum -a 256 -c SHA256SUMS
```

で配布物の改竄検知ができます。

## Docker (source build)

```bash
cd misaka-core-v4/docker
docker compose up -d
```

## ソースからビルド

```bash
cd misaka-core-v4
cargo build --release -p misaka-node --features dag,testnet
```

必要な依存: Rust stable (rustup)、clang / libclang、cmake。RocksDB bindgen が
`stdbool.h` を要求するため、一部の minimal Linux image では `libc-dev` /
`clang` の追加インストールが必要になることがあります。

## 技術仕様

- **署名**: ML-DSA-65 (FIPS 204, Post-Quantum)
- **鍵交換 (P2P)**: ML-KEM-768 (FIPS 203) + ChaCha20-Poly1305 AEAD
- **コンセンサス**: Narwhal DAG-based BFT (Mysticeti-equivalent)
- **ブロック時間**: ~2 秒 (fast lane)
- **Chain ID**: 2 (testnet)

## 運用上の注意

### ブロック放送チャネル

内部の `block_broadcast_tx` チャネルは容量 **500** のバウンドされた
`tokio::mpsc` で、コンセンサスループはここに新規ブロックを **non-blocking
で送信 (`try_send`)** します。

- チャネルが満杯のとき、ノードは **新規ブロックをドロップ** して `Block
  broadcast channel full` を WARN ログに出します。この挙動は意図的で、
  コンセンサスループを P2P バックプレッシャで詰まらせないためのものです。
- 深刻な P2P 遅延下（数十〜数百ブロック規模の一時的な山）ではブロック
  ドロップが発生する可能性があり、そのノードからは自分の提案ブロックが
  ピアに配信されない場合があります。
- 長時間 `Block broadcast channel full` が出続ける場合は、P2P ピアが
  追いついていない・ネットワーク遅延が増大している・受信側が停止している
  などを疑ってください。

### WAL ストア

プロダクションビルド (`--features dag,testnet` ) では **WAL ストア必須**です。
`spawn_consensus_runtime` が `store = None` で呼ばれると即 `panic` します
（v0.5.6 以降、環境変数による bypass は削除済み。WAL-less はテスト専用の
 `test-utils` feature でのみ許可）。

## 補足

- 一般参加者向けの入口は `start-public-node.*` のみです。
- Docker 向け設定と source は `misaka-core-v4` に入っています。
- クロスプラットフォームビルドは GitHub Actions で自動化されています。
