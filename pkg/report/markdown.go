package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"kinsta-log-analyzer/pkg/analyzer"
)

type MarkdownReporter struct {
	outputDir string
}

func NewMarkdownReporter(outputDir string) *MarkdownReporter {
	return &MarkdownReporter{
		outputDir: outputDir,
	}
}

func (r *MarkdownReporter) GenerateReport(result *analyzer.AnalysisResult) (string, error) {
	// Ensure output directory exists
	if err := os.MkdirAll(r.outputDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory: %v", err)
	}

	// Generate filename with timestamp
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("analysis_report_%s.md", timestamp)
	filepath := filepath.Join(r.outputDir, filename)

	// Generate markdown content
	content := r.generateMarkdown(result)

	// Write to file
	if err := os.WriteFile(filepath, []byte(content), 0644); err != nil {
		return "", fmt.Errorf("failed to write report file: %v", err)
	}

	return filepath, nil
}

func (r *MarkdownReporter) generateMarkdown(result *analyzer.AnalysisResult) string {
	var sb strings.Builder

	// Header
	sb.WriteString("# Kinsta アクセスログ解析レポート\n\n")
	sb.WriteString(fmt.Sprintf("**生成日時:** %s\n\n", time.Now().Format("2006-01-02 15:04:05")))

	// Summary section
	r.writeSummary(&sb, result.Summary)

	// HTTP Errors section
	r.writeHTTPErrors(&sb, result.HTTPErrors)

	// Security Analysis section
	r.writeSecurityAnalysis(&sb, result.SecurityAnalysis)

	// Statistics section
	r.writeStatistics(&sb, result.Statistics)

	// User Agent Analysis section
	r.writeUserAgentAnalysis(&sb, result.UserAgentAnalysis)

	// Footer
	sb.WriteString("\n---\n")
	sb.WriteString("🤖 Generated with [Claude Code](https://claude.ai/code)\n")

	return sb.String()
}

func (r *MarkdownReporter) writeSummary(sb *strings.Builder, summary analyzer.Summary) {
	sb.WriteString("## 概要\n\n")
	sb.WriteString(fmt.Sprintf("- **解析期間:** %s - %s\n",
		summary.StartTime.Format("2006-01-02 15:04:05"),
		summary.EndTime.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("- **総リクエスト数:** %s\n", formatNumber(summary.TotalRequests)))
	sb.WriteString(fmt.Sprintf("- **エラー率:** %.2f%%\n", summary.ErrorRate))
	sb.WriteString(fmt.Sprintf("- **平均レスポンス時間:** %.3f秒\n\n", summary.AvgResponseTime))
}

func (r *MarkdownReporter) writeHTTPErrors(sb *strings.Builder, errors analyzer.HTTPErrors) {
	sb.WriteString("## HTTPエラー\n\n")

	// 4xx Errors
	sb.WriteString("### 4xxエラー（クライアントエラー）\n\n")
	if len(errors.ClientErrors) > 0 {
		for status, count := range errors.ClientErrors {
			statusText := getStatusText(status)
			sb.WriteString(fmt.Sprintf("- **%d %s:** %sリクエスト\n", status, statusText, formatNumber(count)))
		}
	} else {
		sb.WriteString("4xxエラーは検出されませんでした。\n")
	}
	sb.WriteString("\n")

	// 5xx Errors
	sb.WriteString("### 5xxエラー（サーバーエラー）\n\n")
	if len(errors.ServerErrors) > 0 {
		for status, count := range errors.ServerErrors {
			statusText := getStatusText(status)
			sb.WriteString(fmt.Sprintf("- **%d %s:** %sリクエスト\n", status, statusText, formatNumber(count)))
		}
	} else {
		sb.WriteString("5xxエラーは検出されませんでした。\n")
	}
	sb.WriteString("\n")

	// Top Error URLs
	sb.WriteString("### エラー頻発URL（上位）\n\n")
	if len(errors.TopErrorURLs) > 0 {
		for i, urlError := range errors.TopErrorURLs {
			sb.WriteString(fmt.Sprintf("%d. `%s`: %sエラー\n", i+1, urlError.URL, formatNumber(urlError.Count)))
		}
	} else {
		sb.WriteString("エラーURLは見つかりませんでした。\n")
	}
	sb.WriteString("\n")
}

func (r *MarkdownReporter) writeSecurityAnalysis(sb *strings.Builder, security analyzer.SecurityAnalysis) {
	sb.WriteString("## セキュリティ分析\n\n")

	// SQL Injection
	sb.WriteString("### SQLインジェクション攻撃\n\n")
	sb.WriteString(fmt.Sprintf("- **攻撃試行数:** %s\n", formatNumber(security.SQLInjectionAttempts)))
	
	if security.SQLInjectionAttempts > 0 {
		sb.WriteString("- **主要攻撃IP:**\n")
		count := 0
		for _, ip := range security.SuspiciousIPs {
			if ip.SQLAttempts > 0 && count < 5 {
				sb.WriteString(fmt.Sprintf("  - %s: %d回の攻撃\n", ip.IP, ip.SQLAttempts))
				count++
			}
		}
	}
	sb.WriteString("\n")

	// XSS Attempts
	sb.WriteString("### XSS攻撃\n\n")
	sb.WriteString(fmt.Sprintf("- **攻撃試行数:** %s\n", formatNumber(security.XSSAttempts)))
	
	if security.XSSAttempts > 0 {
		sb.WriteString("- **主要攻撃IP:**\n")
		count := 0
		for _, ip := range security.SuspiciousIPs {
			if ip.XSSAttempts > 0 && count < 5 {
				sb.WriteString(fmt.Sprintf("  - %s: %d回の攻撃\n", ip.IP, ip.XSSAttempts))
				count++
			}
		}
	}
	sb.WriteString("\n")

	// Suspicious IPs (Recommended for blocking)
	sb.WriteString("### 疑わしいIP（ブロック推奨）\n\n")
	if len(security.SuspiciousIPs) > 0 {
		for i, ip := range security.SuspiciousIPs {
			if i >= 10 { // Limit to top 10
				break
			}
			reasons := []string{}
			if ip.SQLAttempts > 0 {
				reasons = append(reasons, fmt.Sprintf("SQLインジェクション: %d回", ip.SQLAttempts))
			}
			if ip.XSSAttempts > 0 {
				reasons = append(reasons, fmt.Sprintf("XSS: %d回", ip.XSSAttempts))
			}
			sb.WriteString(fmt.Sprintf("%d. **%s** - %s（総リクエスト数: %d）\n", 
				i+1, ip.IP, strings.Join(reasons, "、"), ip.TotalRequests))
		}
	} else {
		sb.WriteString("疑わしいIPは検出されませんでした。\n")
	}
	sb.WriteString("\n")
}

func (r *MarkdownReporter) writeStatistics(sb *strings.Builder, stats analyzer.Statistics) {
	sb.WriteString("## 統計情報\n\n")

	// Hourly Access Pattern
	sb.WriteString("### 時間別アクセス統計\n\n")
	sb.WriteString("| 時間 | リクエスト数 |\n")
	sb.WriteString("|------|----------|\n")
	for hour, count := range stats.HourlyPattern {
		sb.WriteString(fmt.Sprintf("| %02d:00-%02d:00 | %s |\n", hour, hour+1, formatNumber(count)))
	}
	sb.WriteString("\n")

	// Top IPs
	sb.WriteString("### 頻出IPアドレス（上位）\n\n")
	if len(stats.TopIPs) > 0 {
		for i, ip := range stats.TopIPs {
			sb.WriteString(fmt.Sprintf("%d. **%s:** %sリクエスト\n", i+1, ip.IP, formatNumber(ip.Count)))
		}
	} else {
		sb.WriteString("IPデータがありません。\n")
	}
	sb.WriteString("\n")

	// Response Time Analysis
	sb.WriteString("### レスポンスタイム分析\n\n")
	sb.WriteString(fmt.Sprintf("- **平均:** %.3f秒\n", stats.ResponseTimeStats.Average))
	sb.WriteString(fmt.Sprintf("- **最大:** %.3f秒\n", stats.ResponseTimeStats.Maximum))
	sb.WriteString(fmt.Sprintf("- **95パーセンタイル:** %.3f秒\n", stats.ResponseTimeStats.Percentile95))
	sb.WriteString(fmt.Sprintf("- **遅いリクエスト（3秒超）:** %s\n", formatNumber(stats.ResponseTimeStats.SlowRequests)))
	sb.WriteString("\n")

	// Status Code Distribution
	sb.WriteString("### ステータスコード別集計\n\n")
	sb.WriteString("| ステータスコード | 件数 |\n")
	sb.WriteString("|-------------|-------|\n")
	for status, count := range stats.StatusCodes {
		statusText := getStatusText(status)
		sb.WriteString(fmt.Sprintf("| %d %s | %s |\n", status, statusText, formatNumber(count)))
	}
	sb.WriteString("\n")
}

func (r *MarkdownReporter) writeUserAgentAnalysis(sb *strings.Builder, ua analyzer.UserAgentAnalysis) {
	sb.WriteString("## ユーザーエージェント分析\n\n")

	// Crawlers
	sb.WriteString("### 検出されたクローラー\n\n")
	if len(ua.Crawlers) > 0 {
		for agent, count := range ua.Crawlers {
			sb.WriteString(fmt.Sprintf("- **%s:** %sリクエスト\n", agent, formatNumber(count)))
		}
	} else {
		sb.WriteString("クローラーは検出されませんでした。\n")
	}
	sb.WriteString("\n")

	// Attack Tools
	sb.WriteString("### 検出された攻撃ツール\n\n")
	if len(ua.AttackTools) > 0 {
		for tool, count := range ua.AttackTools {
			sb.WriteString(fmt.Sprintf("- **%s:** %sリクエスト\n", tool, formatNumber(count)))
		}
	} else {
		sb.WriteString("攻撃ツールは検出されませんでした。\n")
	}
	sb.WriteString("\n")

	// Suspicious User Agents
	sb.WriteString("### 不審なユーザーエージェント\n\n")
	if len(ua.SuspiciousUAs) > 0 {
		for i, suspicious := range ua.SuspiciousUAs {
			if i >= 10 { // Limit to top 10
				break
			}
			// Truncate long user agents
			userAgent := suspicious.UserAgent
			if len(userAgent) > 80 {
				userAgent = userAgent[:77] + "..."
			}
			sb.WriteString(fmt.Sprintf("%d. `%s` - %sリクエスト\n", i+1, userAgent, formatNumber(suspicious.Count)))
		}
	} else {
		sb.WriteString("不審なユーザーエージェントは検出されませんでした。\n")
	}
	sb.WriteString("\n")
}

func formatNumber(num int) string {
	if num < 1000 {
		return fmt.Sprintf("%d", num)
	}
	return fmt.Sprintf("%s", addCommas(num))
}

func addCommas(num int) string {
	str := fmt.Sprintf("%d", num)
	if len(str) <= 3 {
		return str
	}
	
	result := ""
	for i, digit := range str {
		if i > 0 && (len(str)-i)%3 == 0 {
			result += ","
		}
		result += string(digit)
	}
	return result
}

func getStatusText(code int) string {
	statusTexts := map[int]string{
		200: "OK",
		301: "Moved Permanently",
		302: "Found",
		304: "Not Modified",
		400: "Bad Request",
		401: "Unauthorized",
		403: "Forbidden",
		404: "Not Found",
		405: "Method Not Allowed",
		429: "Too Many Requests",
		500: "Internal Server Error",
		502: "Bad Gateway",
		503: "Service Unavailable",
		504: "Gateway Timeout",
	}
	
	if text, exists := statusTexts[code]; exists {
		return text
	}
	return "Unknown"
}