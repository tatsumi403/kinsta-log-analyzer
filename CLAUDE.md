# Kinsta Access Log Analyzer

## 概要
KinstaのNginxアクセスログを解析し、HTTPエラー検知、セキュリティ攻撃検出、
統計レポート生成を行う Go 製 CLI。ローカル実行。

## プロジェクト構成
- `cmd/log-analyzer/`        … CLI エントリポイント
- `pkg/parser/`              … Nginx ログ正規表現パーサ
- `pkg/analyzer/`            … 分析エンジン (`analyzer.go`, `stats.go`)
- `pkg/report/markdown.go`   … Markdown レポート生成
- `pkg/config/`              … YAML 設定読み込み
- `pkg/utils/`               … フォーマット系ユーティリティ
- `config.yaml`              … 検知パターン・閾値・出力設定
- `logs/`, `output/`         … 入出力ディレクトリ

## 技術スタック
- Go 1.22+
- 依存: `gopkg.in/yaml.v2` のみ（標準ライブラリ中心）

## 実行
```bash
go build -o log-analyzer ./cmd/log-analyzer
./log-analyzer --input logs/sample-access.log [--verbose]
```
詳細仕様（ログ形式・検知パターン・出力スキーマ）は `config.yaml` と `README.md` を参照。

## 振る舞いガイドライン

### 1. 着手前に考える
- 前提を明示する。曖昧なら止めて質問する。
- 解釈が複数ありうるときは並べて提示し、黙って選ばない。
- よりシンプルな案があれば言う。必要なら押し返す。

### 2. シンプル優先
- 依頼された範囲を超える機能・抽象化・設定項目を勝手に追加しない。
- 起こり得ないシナリオへのエラーハンドリングを書かない。
- 「シニアが過剰だと言わないか?」を自問する。

### 3. 外科的な変更
- 触る必要のない隣接コードを「ついでに改善」しない。
- 既存のスタイル・命名に合わせる。
- 自分の変更で孤児になった import/関数だけ消す。既存の dead code は指摘するに留める。

### 4. ゴール駆動
- 「バグ修正」=「再現テストを書いて通す」など、検証可能な形に置き換える。
- 複数ステップの作業は短い計画と検証ポイントを先に示す。
