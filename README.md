# Kinsta Access Log Analyzer

KinstaのNginxアクセスログを解析し、HTTPエラーの検知・分類、セキュリティ攻撃の検出、統計情報の生成を行うGo製の解析ツール。

## 特徴

- **包括的な分析**: HTTPエラー、セキュリティ攻撃、パフォーマンス、アクセスパターンを網羅的に分析
- **セキュリティ重視**: 27種類のSQLインジェクションと17種類のXSS攻撃パターンを検出
- **高速処理**: ストリーミング処理により大容量ログでもメモリ効率的に解析
- **柔軟な設定**: YAML設定ファイルで検出パターンや閾値をカスタマイズ可能
- **シンプルな実行**: Go環境のみで動作するローカル実行（依存ライブラリは最小限）
- **詳細なレポート**: Markdown形式の見やすいレポートと、実用的な推奨事項を提供
- **ログフォーマット互換**: Kinstaの旧形式（リクエスト全体が `"GET /path HTTP/1.1"` で囲まれる）と、Method/Protocol が unquoted で URI のみ quoted の新形式の両方をパース
- **JST表示**: レポートの生成日時・解析期間・時間別バケットを Asia/Tokyo (JST) で出力
- **エラー深掘り分析**: ステータスコード別エラーURL Top、エラー率の高いUA/IP、短時間エラーバースト検出、遅いリクエストURL Top を出力

## クイックスタート

### ローカル実行（Go環境が必要）

```bash
# 依存関係のダウンロード
go mod download

# アプリケーションのビルド
go build -o log-analyzer ./cmd/log-analyzer

# サンプルログの解析
./log-analyzer --input logs/sample-access.log --verbose

# カスタム設定での実行
./log-analyzer --input /path/to/access.log --config config.yaml --output /custom/output
```

## 設定ファイル

`config.yaml`で解析パラメータをカスタマイズできます：

```yaml
thresholds:
  error_rate_warning: 5.0           # エラー率の警告閾値（%）
  slow_request_time: 3.0            # 遅いリクエストの閾値（秒）
  min_requests_for_error_rate: 50   # UA/IPエラー率算出時の最小総リクエスト数（ノイズ除外）
  burst_window_seconds: 60          # エラーバースト検出のウィンドウ（秒）
  burst_threshold: 20               # ウィンドウ内エラー数がこれを超えるとバースト

security:
  sql_injection_patterns:  # SQLインジェクション検出パターン（27種）
    - "union select"
    - "union all select"
    - "or 1=1"
    - "or '1'='1"
    - "drop table"
    - "insert into"
    - "exec("
    - "xp_cmdshell"
    # ...他19種

  xss_patterns:            # XSS検出パターン（17種）
    - "<script"
    - "javascript:"
    - "onerror="
    - "<iframe"
    - "eval("
    # ...他12種

  crawler_user_agents:     # 正規クローラー（8種）
    - "googlebot"
    - "bingbot"
    - "slurp"
    # ...他5種

  attack_tool_patterns:    # 攻撃ツール検出（16種）
    - "sqlmap"
    - "nikto"
    - "burp"
    - "nmap"
    - "gobuster"
    # ...他11種

output:
  top_ips_count: 10        # 上位IP表示数
  top_errors_count: 10     # 上位エラーURL表示数
  report_format: "markdown"
  output_directory: "./output"
```

## 出力例

### コンソール出力
```
=== Kinsta Log Analysis Summary ===
Analysis Duration: 45.2ms
Report Generated: ./output/analysis_report_20250708_143022.md

Total Requests: 15
Error Rate: 33.33%
Average Response Time: 0.826 seconds

Security Analysis:
  SQL Injection Attempts: 3
  XSS Attempts: 2
  Suspicious IPs: 2

Performance Analysis:
  Slow Requests (>3s): 1
  Max Response Time: 5.120 seconds
  95th Percentile: 1.230 seconds

Top Error URLs:
  1. /admin.php (1 errors)
  2. /page.php (1 errors)
  3. /very/slow/page (1 errors)

Recommendations:
  • 🔒 Consider blocking 2 suspicious IP(s) detected
  • ⚡ Investigate 1 slow requests (>3s response time)
  • ❗ High error rate detected (33.33%) - investigate error causes
  • 🛡️  Implement additional security measures (WAF, rate limiting)

📊 Full report available at: ./output/analysis_report_20250708_143022.md
```

### Markdownレポート

生成されるMarkdownレポートには以下の情報が含まれます：

- **サマリー**: 分析期間（JST）、総リクエスト数、エラー率など
- **HTTPエラー**: 4xx/5xxエラーの詳細、エラー頻発URL、ステータスコード別エラーURL Top（404/500/502/503/504）
- **セキュリティ分析**: 攻撃検出結果、ブロック推奨IP、エラー率の高いIP、エラー連発IP（バースト検出）
- **統計情報**: 時間別アクセス（JST）、時間別 4xx/5xx エラー（該当ログがある場合のみ表示）、上位IP、レスポンスタイム分析、遅いリクエスト URL Top
- **ユーザーエージェント分析**: クローラー、攻撃ツール、不審なUA、エラー頻発ユーザーエージェント

## プロジェクト構造

```
kinsta-log-analyzer/
├── cmd/log-analyzer/     # メインアプリケーション
├── pkg/
│   ├── analyzer/        # ログ分析エンジン
│   ├── config/          # 設定管理
│   ├── parser/          # ログパーサー
│   └── report/          # レポート生成
├── logs/                # ログファイル
├── output/              # 分析結果出力
└── config.yaml          # 設定ファイル
```

## 分析内容

### HTTPエラー分析
- 4xxエラー（クライアントエラー）の検出と分類
- 5xxエラー（サーバーエラー）の検出と分類
- エラー率の計算と警告
- **ステータスコード別エラーURL Top**: 404 / 500 / 502 / 503 / 504 ごとに発生件数の多いURL上位を出力

### セキュリティ分析
- **SQLインジェクション検出**: 27種類の攻撃パターン
  - UNION SELECT、OR 1=1、DROP TABLE、xp_cmdshell等
- **XSS攻撃検出**: 17種類の攻撃パターン
  - `<script>`、javascript:、onerror=、eval()等
- **攻撃元IP特定**: 攻撃試行回数でランク付け
- **ブロック推奨**: 危険なIPアドレスをリストアップ
- **エラー率の高いIP**: 一定リクエスト数以上を投げたIPをエラー率順にランキング
- **エラー連発IP（バースト検出）**: 短時間に大量のエラーを発生させたIPを検出（スキャナー疑い）

### ユーザーエージェント分析
- **正規クローラー識別**: Googlebot、Bingbot等8種類
- **攻撃ツール検出**: sqlmap、nikto、nmap等16種類
- **不審なUA検出**: 自動化ツールやカスタムスクリプト
- **エラー頻発ユーザーエージェント**: 一定リクエスト数以上のUAをエラー率順にランキング

### アクセス統計
- **時間別アクセスパターン**: 24時間の分布（JST）
- **時間別エラー統計**: 4xx/5xx の時間別件数（JST、該当エラーがある場合のみ表として出力）
- **頻出IPアドレス**: リクエスト数上位10件
- **エラー頻発URL**: エラー発生数上位10件
- **ステータスコード分布**: 全ステータスコード集計

### パフォーマンス分析
- **レスポンスタイム統計**: 平均、最大、95パーセンタイル
- **遅延リクエスト検出**: 3秒超過の詳細リスト
- **遅いリクエスト URL Top**: 閾値超過リクエストのURLを件数順にランキング
- **処理時間分析**: パフォーマンスボトルネックの特定

## テスト

```bash
# 全テストの実行
go test ./...

# 特定パッケージのテスト
go test ./pkg/parser -v

# カバレッジ付きテスト
go test ./... -cover
```

## 技術仕様

### 実装
- **言語**: Go 1.22+
- **依存ライブラリ**: gopkg.in/yaml.v2（最小限の依存）
- **アーキテクチャ**: パイプライン処理（パース→分析→レポート）
- **ログ処理**: 正規表現ベースのストリーミング解析（Kinsta旧/新フォーマット両対応）

### パフォーマンス
- **メモリ効率**: ストリーミング処理により大容量ログでも低メモリ使用量
- **処理速度**: 15行のサンプルログを45ms以内で処理
- **スケーラビリティ**: 100MB以上のログファイルに対応

## 使用例

### 基本的な使用
```bash
# サンプルログを解析
./log-analyzer --input logs/sample-access.log

# 詳細なログ出力で実行
./log-analyzer --input logs/sample-access.log --verbose

# カスタム出力先を指定
./log-analyzer --input logs/access.log --output ./reports
```

### カスタム設定での実行
```bash
# カスタム設定ファイルを使用
./log-analyzer --input logs/access.log --config custom-config.yaml

# 複数オプションを組み合わせ
./log-analyzer --input logs/access.log --config config.yaml --output ./reports --verbose
```

## 出力ファイル

解析完了後、以下のファイルが生成されます：

- `output/analysis_report_YYYYMMDD_HHMMSS.md`: 詳細な分析レポート（Markdown形式）

レポートには以下のセクションが含まれます（時刻系はすべて JST 表示）：
1. サマリー（解析期間、総リクエスト数、エラー率、平均レスポンスタイム）
2. HTTPエラー詳細（4xx/5xxエラー、エラー頻発URL、ステータスコード別エラーURL Top）
3. セキュリティ分析（SQLi/XSS検出結果、ブロック推奨IP、エラー率の高いIP、エラー連発IP（バースト検出））
4. 統計情報（時間別アクセス、時間別 4xx/5xx エラー（該当時のみ）、上位IP、エラーURL）
5. レスポンスタイム分析（平均/最大/95パーセンタイル、遅いリクエスト URL Top）
6. ユーザーエージェント分析（クローラー、攻撃ツール、不審なUA、エラー頻発UA）

## トラブルシューティング

### ログファイルが見つからない
```bash
# ファイルパスを確認
ls -la logs/

# 絶対パスを使用
./log-analyzer --input /full/path/to/access.log
```

### 設定ファイルの読み込みエラー
```bash
# YAML構文を確認
cat config.yaml

# デフォルト設定で実行
./log-analyzer --input logs/sample-access.log
```

## ライセンス

このプロジェクトは MIT ライセンスの下で公開されています。
