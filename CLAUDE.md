## Gemini CLI 連携ガイド

### 目的
ユーザーが **「Geminiと相談しながら進めて」** と指示した場合、
Claude は以降のタスクを **Gemini CLI** と協調しながら進める。

### トリガー
- 正規表現: `/Gemini.*相談しながら/`

### 基本フロー
1. **PROMPT 生成**
   Claude はユーザーの要件を1つのテキストにまとめ、環境変数 `$PROMPT` に格納

2. **Gemini CLI 呼び出し**
```bash
gemini <<EOF
$PROMPT
EOF
```

3. **結果の統合**
   - Gemini の回答を提示
   - Claude の追加分析・コメントを付加

---

# Kinsta Access Log Analyzer

## 概要
KinstaのNginxアクセスログを解析し、HTTPエラーの検知・分類、セキュリティ攻撃の検出、統計情報の生成を行うGo製の解析ツール。
Docker/Docker Composeによる簡単なデプロイと、ローカル実行の両方に対応。

## ログ形式
```
kinstahelptesting.kinsta.cloud 98.43.13.94 [22/Sep/2021:21:26:10 +0000] GET "/wp-admin/" HTTP/1.0 302 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:92.0) Gecko/20100101 Firefox/92.0" 98.43.13.94 "/wp-admin/index.php" - - 472 0.562 0.560
```

フィールド構成:
- domain
- client_ip  
- timestamp
- method
- uri
- protocol
- status_code
- referer
- user_agent
- real_ip
- upstream_uri
- response_size
- response_time

## 機能要件

### 1. HTTPエラー検知・分類
- 4xxエラー（クライアントエラー）の検出と分類
- 5xxエラー（サーバーエラー）の検出と分類
- エラー率の計算

### 2. セキュリティ攻撃検知
- SQLインジェクション攻撃パターン検知
  - `UNION SELECT`, `OR 1=1`, `' OR '1'='1`, `DROP TABLE` 等
- XSS攻撃パターン検知  
  - `<script>`, `javascript:`, `onerror=`, `onload=` 等
- 怪しいIPアドレスの特定と推奨

### 3. ユーザーエージェント分析
- 一般的なクローラーの識別（Googlebot, Bingbot等）
- 攻撃用ツールの検出（sqlmap, nikto等）
- 不審なUser-Agentパターンの検出

### 4. 統計情報生成
- 時間別アクセス統計（24時間）
- 頻出IPアドレス（上位10位）
- エラー頻発URL（上位10位）  
- レスポンスタイム分析（平均、最大、95パーセンタイル）
- ステータスコード別集計

## 技術仕様

### 実行環境
- Docker containerで動作
- ローカル実行を前提
- 単一ログファイル処理（最大数100MB想定）

### 実行方法

#### ローカル実行
```bash
# ビルド
go build -o log-analyzer ./cmd/log-analyzer

# 実行（基本）
./log-analyzer --input logs/sample-access.log

# 実行（詳細出力）
./log-analyzer --input logs/sample-access.log --verbose

# カスタム設定
./log-analyzer --input logs/access.log --config config.yaml --output ./custom-output
```

#### Docker実行
```bash
# イメージビルド
docker build -t kinsta-log-analyzer .

# 実行
docker run -v $(pwd)/logs:/app/logs -v $(pwd)/output:/app/output \
  kinsta-log-analyzer --input /app/logs/access.log-2025-07-08-xxxxxxxxxx
```

#### Docker Compose実行
```bash
# サンプルログ解析
docker-compose run log-analyzer --input /app/logs/sample-access.log --verbose

# カスタムログ解析
docker-compose run log-analyzer --input /app/logs/your-log-file.log
```

### 設定ファイル
`config.yaml`:
```yaml
thresholds:
  error_rate_warning: 5.0  # エラー率警告閾値（%）
  slow_request_time: 3.0   # 遅延リクエスト閾値（秒）

security:
  sql_injection_patterns:  # SQLi検出パターン（27種）
    - "union select"
    - "union all select"
    - "or 1=1"
    - "or '1'='1"
    - "drop table"
    - "insert into"
    - "exec("
    - "xp_cmdshell"
    # ...他23種

  xss_patterns:            # XSS検出パターン（17種）
    - "<script"
    - "javascript:"
    - "onerror="
    - "onload="
    - "<iframe"
    - "eval("
    - "document.cookie"
    # ...他10種

  crawler_user_agents:     # クローラー識別（8種）
    - "googlebot"
    - "bingbot"
    - "slurp"
    - "duckduckbot"
    # ...他4種

  attack_tool_patterns:    # 攻撃ツール検出（16種）
    - "sqlmap"
    - "nikto"
    - "burp"
    - "zaproxy"
    - "gobuster"
    - "nmap"
    - "nuclei"
    - "ffuf"
    # ...他8種

output:
  top_ips_count: 10        # 上位IP表示数
  top_errors_count: 10     # 上位エラーURL表示数
  report_format: "markdown"
  output_directory: "./output"
```

## 出力仕様

### レポートファイル
`output/analysis_report_YYYYMMDD_HHMMSS.md`

#### レポート構成
```markdown
# Kinsta Access Log Analysis Report

## Summary
- 解析期間: 2025-07-08 00:00:00 - 23:59:59
- 総リクエスト数: 123,456
- エラー率: 2.3%
- 平均レスポンスタイム: 0.245秒

## HTTP Errors
### 4xx Errors (Client Errors)
- 404 Not Found: 1,234 requests
- 403 Forbidden: 234 requests
- 400 Bad Request: 123 requests

### 5xx Errors (Server Errors)  
- 500 Internal Server Error: 45 requests
- 502 Bad Gateway: 12 requests

## Security Analysis
### SQL Injection Attempts
- 検出件数: 23
- 主要攻撃IP: xxx.xxx.xxx.xxx (15 attempts)

### XSS Attempts  
- 検出件数: 8
- 主要攻撃IP: yyy.yyy.yyy.yyy (5 attempts)

### Suspicious IPs (推奨ブロック対象)
1. xxx.xxx.xxx.xxx - SQL injection attempts: 15
2. yyy.yyy.yyy.yyy - XSS attempts: 5

## Statistics
### Hourly Access Pattern
00:00-01:00: 2,345 requests
01:00-02:00: 1,234 requests
...

### Top 10 IPs by Request Count
1. xxx.xxx.xxx.xxx: 1,234 requests
2. yyy.yyy.yyy.yyy: 567 requests
...

### Top 10 Error URLs
1. /wp-admin/admin-ajax.php: 234 errors
2. /wp-login.php: 123 errors
...

### Response Time Analysis
- 平均: 0.245秒
- 最大: 15.2秒  
- 95パーセンタイル: 1.2秒
- 3秒超過リクエスト: 45件

## User Agent Analysis
### Crawlers Detected
- Googlebot: 1,234 requests
- Bingbot: 567 requests

### Suspicious User Agents
- sqlmap/1.0: 15 requests
- nikto/2.0: 8 requests
```

## 実装状況

### 完成済み機能
✅ **コア機能**
- Nginxログパーサー（正規表現ベース）
- ストリーミング処理によるメモリ効率化
- 設定ファイル（YAML）による柔軟なカスタマイズ
- コマンドラインインターフェース（フラグ対応）

✅ **分析機能**
- HTTPエラー検知・分類（4xx/5xx）
- セキュリティ攻撃検知（SQLi/XSS）
- ユーザーエージェント分析（クローラー/攻撃ツール）
- 時間別アクセス統計
- IPアドレス分析
- レスポンスタイム分析（平均/最大/95パーセンタイル）
- ステータスコード別集計

✅ **レポート機能**
- Markdownレポート生成
- コンソールサマリー表示
- 推奨アクション提示
- 詳細な統計情報

✅ **デプロイ**
- Dockerサポート（マルチステージビルド）
- Docker Compose設定
- サンプルログファイル同梱

### プロジェクト構造
```
kinsta-log-analyzer/
├── cmd/log-analyzer/     # メインアプリケーション
│   └── main.go          # CLI、サマリー表示、推奨事項
├── pkg/
│   ├── analyzer/        # 分析エンジン
│   │   └── analyzer.go  # コア分析ロジック
│   ├── config/          # 設定管理
│   │   └── config.go    # YAML設定読み込み
│   ├── parser/          # ログパーサー
│   │   └── parser.go    # 正規表現ベースパーサー
│   └── report/          # レポート生成
│       └── report.go    # Markdown生成
├── logs/                # ログファイル
│   └── sample-access.log # サンプルログ
├── output/              # 分析結果出力
├── config.yaml          # 設定ファイル
├── Dockerfile           # Docker設定
├── docker-compose.yml   # Docker Compose設定
└── .gitignore           # Git除外設定

### 技術スタック
- **言語**: Go 1.22+
- **ライブラリ**:
  - gopkg.in/yaml.v3（YAML解析）
  - 標準ライブラリのみ（依存最小化）
- **コンテナ**: Docker（Alpine Linuxベース）
- **ビルドツール**: Go modules

### パフォーマンス特性
- メモリ使用量: ストリーミング処理により最小化
- 処理速度: 15行のサンプルログを45ms以内で処理
- コンテナサイズ: マルチステージビルドで最適化
