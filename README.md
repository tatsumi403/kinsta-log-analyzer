# Kinsta Access Log Analyzer

KinstaのNginxアクセスログを解析し、HTTPエラーの検知・分類、セキュリティ攻撃の検出、統計情報の生成を行うDockerベースの解析ツール。

## 機能

- **HTTPエラー解析**: 4xx/5xxエラーの検知と分類
- **セキュリティ分析**: SQLインジェクション、XSS攻撃の検出
- **統計情報生成**: 時間別アクセス、頻出IP、レスポンスタイム分析
- **ユーザーエージェント分析**: クローラー、攻撃ツールの識別
- **Markdownレポート**: 詳細な分析結果をMarkdown形式で出力

## クイックスタート

### 1. ローカル実行（Go環境が必要）

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

### 2. Docker実行

```bash
# Dockerイメージのビルド
docker build -t kinsta-log-analyzer .

# サンプルログの解析
docker run -v $(pwd)/logs:/app/logs -v $(pwd)/output:/app/output \
  kinsta-log-analyzer --input /app/logs/sample-access.log --verbose

# カスタムログファイルの解析
docker run -v /path/to/logs:/app/logs -v $(pwd)/output:/app/output \
  kinsta-log-analyzer --input /app/logs/access.log-2025-07-08-xxxxxxxxxx
```

### 3. Docker Compose実行

```bash
# ヘルプを表示
docker-compose run log-analyzer

# サンプルログを解析
docker-compose run log-analyzer --input /app/logs/sample-access.log --verbose

# カスタムログファイルを解析
docker-compose run log-analyzer --input /app/logs/your-log-file.log --output /app/output
```

## 設定ファイル

`config.yaml`で解析パラメータをカスタマイズできます：

```yaml
thresholds:
  error_rate_warning: 5.0  # エラー率の警告閾値（%）
  slow_request_time: 3.0   # 遅いリクエストの閾値（秒）

security:
  sql_injection_patterns:  # SQLインジェクション検出パターン
    - "union select"
    - "or 1=1"
    # ...
  
  xss_patterns:           # XSS検出パターン
    - "<script"
    - "javascript:"
    # ...

output:
  top_ips_count: 10       # 上位IP表示数
  top_errors_count: 10    # 上位エラーURL表示数
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

- **サマリー**: 分析期間、総リクエスト数、エラー率など
- **HTTPエラー**: 4xx/5xxエラーの詳細
- **セキュリティ分析**: 攻撃検出結果と推奨ブロック対象IP
- **統計情報**: 時間別アクセス、上位IP、レスポンスタイム分析
- **ユーザーエージェント分析**: クローラー、攻撃ツール、不審なUA

## プロジェクト構造

```
kinsta-log-analyzer/
├── cmd/log-analyzer/     # メインアプリケーション
├── pkg/
│   ├── analyzer/        # ログ分析エンジン
│   ├── config/          # 設定管理
│   ├── parser/          # ログパーサー
│   └── report/          # レポート生成
├── logs/                # ログファイル（マウント用）
├── output/              # 分析結果出力
├── config.yaml          # 設定ファイル
├── Dockerfile           # Docker設定
└── docker-compose.yml   # Docker Compose設定
```

## テスト

```bash
# 全テストの実行
go test ./...

# 特定パッケージのテスト
go test ./pkg/parser -v

# カバレッジ付きテスト
go test ./... -cover
```

## パフォーマンス

- **メモリ効率**: ストリーミング処理により、大きなログファイルでも低メモリ使用量
- **高速処理**: 並行処理とGoroutineを活用した高速分析
- **軽量Docker**: マルチステージビルドによる最適化されたイメージサイズ

## ライセンス

このプロジェクトは MIT ライセンスの下で公開されています。

## 貢献

バグレポートや機能リクエストは、GitHubのIssuesでお知らせください。プルリクエストも歓迎します。

---

🤖 Generated with [Claude Code](https://claude.ai/code)