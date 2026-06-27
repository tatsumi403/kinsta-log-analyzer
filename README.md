# Kinsta Access Log Analyzer

KinstaのNginxアクセスログを解析し、HTTPエラーの検知・分類、セキュリティ攻撃の検出、統計情報の生成を行うGo製の解析ツール。

## 特徴

- **包括的な分析**: HTTPエラー、セキュリティ攻撃、パフォーマンス、アクセスパターンを網羅的に分析
- **セキュリティ重視**: 20種類のSQLインジェクションと18種類のXSS攻撃パターンを検出
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

# サンプルログの解析（config.yaml が自動的に読み込まれる）
./log-analyzer --input logs/sample-access.log --verbose

# 出力先を変更して実行（--config 省略時は config.yaml をデフォルトで使用）
./log-analyzer --input /path/to/access.log --output /custom/output

# ショートハンドフラグ（-i = --input, -o = --output）
./log-analyzer -i logs/sample-access.log -o ./reports
```

## 設定ファイル

`config.yaml` で解析パラメータをカスタマイズできます。`--config` を省略した場合、以下の順で `config.yaml` を自動検索します：

1. カレントディレクトリ
2. 実行ファイルと同じディレクトリ
3. `~/.config/kinsta-log-analyzer/config.yaml`（`go install` でどこからでも実行する場合はここに置く）


```yaml
thresholds:
  error_rate_warning: 5.0           # エラー率の警告閾値（%）
  slow_request_time: 3.0            # 遅いリクエストの閾値（秒）
  min_requests_for_error_rate: 50   # UA/IPエラー率算出時の最小総リクエスト数（ノイズ除外）
  burst_window_seconds: 60          # エラーバースト検出のウィンドウ（秒）
  burst_threshold: 20               # ウィンドウ内エラー数がこれを超えるとバースト

security:
  sql_injection_patterns:  # SQLインジェクション検出パターン（20種）
    - "union select"
    - "union all select"
    - "or 1=1"
    - "or '1'='1"
    - "drop table"
    - "insert into"
    - "exec("
    - "xp_cmdshell"
    # ...他12種

  xss_patterns:            # XSS検出パターン（18種）
    - "<script"
    - "javascript:"
    - "onerror="
    - "<iframe"
    - "eval("
    # ...他13種

  crawler_user_agents:     # 正規クローラー（8種）
    - "googlebot"
    - "bingbot"
    - "slurp"
    # ...他5種

  attack_tool_patterns:    # 攻撃ツール検出（17種）
    - "sqlmap"
    - "nikto"
    - "burp"
    - "nmap"
    - "gobuster"
    # ...他12種

output:
  top_ips_count: 10        # 上位IP表示数
  top_errors_count: 10     # 上位エラーURL表示数
  report_format: "markdown"
  output_directory: "./output"
```

## 出力例

### コンソール出力
```
=== Kinsta ログ解析結果 ===
解析時間: 45.2ms
レポート生成: ./output/analysis_report_20250708_143022.md

総リクエスト数: 15
エラー率: 33.33%
平均レスポンス時間: 0.826秒

セキュリティ分析:
  SQLインジェクション試行: 3
  XSS試行: 2
  疑わしいIP: 2

パフォーマンス分析:
  遅いリクエスト(3秒超): 1
  最大レスポンス時間: 5.120秒
  95パーセンタイル: 1.230秒

エラー頻発URL:
  1. /admin.php (1エラー)
  2. /page.php (1エラー)
  3. /very/slow/page (1エラー)

推奨事項:
  • 🔒 疑わしいIP 2件のブロックを検討してください
  • ⚡ 遅いリクエスト 1件(3秒超)の調査をお勧めします
  • ❗ 高いエラー率 (33.33%) - エラー原因の調査が必要です
  • 🛡️  追加のセキュリティ対策 (WAF、レート制限)の実装をお勧めします

📊 詳細レポート: ./output/analysis_report_20250708_143022.md
```

### Markdownレポート

生成されるMarkdownレポートには以下の情報が含まれます：

- **サマリー**: 分析期間（JST）、総リクエスト数、エラー率など
- **HTTPエラー**: 4xx/5xxエラーの詳細、エラー頻発URL、ステータスコード別エラーURL Top（404/500/502/503/504）
- **セキュリティ分析**: 攻撃検出結果、ブロック推奨IP（攻撃観点/エラー観点）、エラー率の高いIP、エラー連発IP（バースト検出）
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
- **SQLインジェクション検出**: 20種類の攻撃パターン
  - UNION SELECT、OR 1=1、DROP TABLE、xp_cmdshell等
- **XSS攻撃検出**: 18種類の攻撃パターン
  - `<script>`、javascript:、onerror=、eval()等
- **攻撃元IP特定**: 攻撃試行回数でランク付け
- **ブロック推奨**: 危険なIPアドレスをリストアップ
- **エラー率の高いIP**: 一定リクエスト数以上を投げたIPをエラー率順にランキング
- **エラー連発IP（バースト検出）**: 短時間に大量のエラーを発生させたIPを検出（スキャナー疑い）
- **疑わしいIP（エラー観点 / ブロック推奨）**: 高エラー率・バーストの2観点を統合し、どちらか/両方に該当するIPをまとめてランキング（両観点該当を優先）

### ユーザーエージェント分析
- **正規クローラー識別**: Googlebot、Bingbot等8種類
- **攻撃ツール検出**: sqlmap、nikto、nmap等17種類
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

# ショートハンド（-i / -o）でも同じ
./log-analyzer -i logs/access.log -o ./reports
```

### カスタム設定での実行
```bash
# カスタム設定ファイルを使用
./log-analyzer --input logs/access.log --config custom-config.yaml

# 複数オプションを組み合わせ（--config 省略で config.yaml を自動使用）
./log-analyzer --input logs/access.log --output ./reports --verbose
```

## 出力ファイル

解析完了後、以下のファイルが生成されます：

- `output/analysis_report_YYYYMMDD_HHMMSS.md`: 詳細な分析レポート（Markdown形式）

レポートには以下のセクションが含まれます（時刻系はすべて JST 表示）：
1. サマリー（解析期間、総リクエスト数、エラー率、平均レスポンスタイム）
2. HTTPエラー詳細（4xx/5xxエラー、エラー頻発URL、ステータスコード別エラーURL Top）
3. セキュリティ分析（SQLi/XSS検出結果、ブロック推奨IP（攻撃観点/エラー観点）、エラー率の高いIP、エラー連発IP（バースト検出））
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
# config.yaml がカレントディレクトリまたは実行ファイルと同じディレクトリに存在するか確認
ls config.yaml

# YAML構文を確認
cat config.yaml

# 別の場所にある設定ファイルを明示的に指定
./log-analyzer --input logs/sample-access.log --config /path/to/config.yaml
```

## ライセンス

このプロジェクトは MIT ライセンスの下で公開されています。
