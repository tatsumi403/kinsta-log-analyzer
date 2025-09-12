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


# Kinsta Access Log Analyzer

## 概要
KinstaのNginxアクセスログを解析し、HTTPエラーの検知・分類、セキュリティ攻撃の検出、統計情報の生成を行うDockerベースの解析ツール。

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
```bash
docker run -v ./logs:/app/logs -v ./config:/app/config -v ./output:/app/output kinsta-log-analyzer --input /app/logs/access.log-2025-07-08-xxxxxxxxxx
```

### 設定ファイル
`config/analyzer.yaml`:
```yaml
thresholds:
  error_rate_warning: 5.0  # %
  slow_request_time: 3.0   # seconds
  
security:
  sql_injection_patterns:
    - "union select"
    - "or 1=1"
    - "drop table"
  xss_patterns:
    - "<script"
    - "javascript:"
    - "onerror="
    
output:
  top_ips_count: 10
  top_errors_count: 10
  report_format: "markdown"
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

## 実装指針
- 高速処理のためGo言語を推奨
- 正規表現による効率的なログパース
- メモリ効率を考慮したストリーミング処理
- 設定ファイルによる柔軟なカスタマイズ
- 詳細なエラーハンドリングとログ出力
