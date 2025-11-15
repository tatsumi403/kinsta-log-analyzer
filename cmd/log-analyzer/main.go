package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"kinsta-log-analyzer/pkg/analyzer"
	"kinsta-log-analyzer/pkg/config"
	"kinsta-log-analyzer/pkg/report"
	"kinsta-log-analyzer/pkg/utils"
)

var (
	version = "1.0.0"
	
	inputFile  = flag.String("input", "", "Path to the log file to analyze (required)")
	configFile = flag.String("config", "config.yaml", "Path to the configuration file")
	outputDir  = flag.String("output", "./output", "Output directory for reports")
	showVersion = flag.Bool("version", false, "Show version information")
	verbose    = flag.Bool("verbose", false, "Enable verbose logging")
)

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Printf("Kinsta Log Analyzer v%s\n", version)
		fmt.Println("A tool for analyzing Kinsta Nginx access logs")
		os.Exit(0)
	}

	if *inputFile == "" {
		fmt.Fprintf(os.Stderr, "Error: --input flag is required\n")
		flag.Usage()
		os.Exit(1)
	}

	// Check if input file exists
	if _, err := os.Stat(*inputFile); os.IsNotExist(err) {
		log.Fatalf("Error: Input file does not exist: %s", *inputFile)
	}

	// Load configuration
	if *verbose {
		log.Printf("Loading configuration from: %s", *configFile)
	}
	
	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Override output directory if specified via command line
	if *outputDir != "./output" {
		cfg.Output.OutputDirectory = *outputDir
	}

	// Create analyzer
	analyzer := analyzer.NewAnalyzer(cfg)

	// Analyze the log file
	if *verbose {
		log.Printf("Starting analysis of: %s", *inputFile)
	}
	
	startTime := time.Now()
	result, err := analyzer.AnalyzeFile(*inputFile)
	if err != nil {
		log.Fatalf("Analysis failed: %v", err)
	}
	duration := time.Since(startTime)

	if *verbose {
		log.Printf("Analysis completed in %v", duration)
		log.Printf("Processed %d requests", result.Summary.TotalRequests)
	}

	// Generate report
	if *verbose {
		log.Printf("Generating report in: %s", cfg.Output.OutputDirectory)
	}

	reporter := report.NewMarkdownReporter(cfg.Output.OutputDirectory)
	reportPath, err := reporter.GenerateReport(result)
	if err != nil {
		log.Fatalf("Failed to generate report: %v", err)
	}

	// Print summary to console
	printSummary(result, reportPath, duration)
}

func printSummary(result *analyzer.AnalysisResult, reportPath string, duration time.Duration) {
	fmt.Println("=== Kinsta ログ解析結果 ===")
	fmt.Printf("解析時間: %v\n", duration)
	fmt.Printf("レポート生成: %s\n\n", reportPath)

	// Basic statistics
	fmt.Printf("総リクエスト数: %s\n", utils.FormatNumber(result.Summary.TotalRequests))
	fmt.Printf("エラー率: %.2f%%\n", result.Summary.ErrorRate)
	fmt.Printf("平均レスポンス時間: %.3f秒\n\n", result.Summary.AvgResponseTime)

	// Security summary
	fmt.Println("セキュリティ分析:")
	fmt.Printf("  SQLインジェクション試行: %s\n", utils.FormatNumber(result.SecurityAnalysis.SQLInjectionAttempts))
	fmt.Printf("  XSS試行: %s\n", utils.FormatNumber(result.SecurityAnalysis.XSSAttempts))
	fmt.Printf("  疑わしいIP: %d\n\n", len(result.SecurityAnalysis.SuspiciousIPs))

	// Performance summary
	fmt.Println("パフォーマンス分析:")
	fmt.Printf("  遅いリクエスト(3秒超): %s\n", utils.FormatNumber(result.Statistics.ResponseTimeStats.SlowRequests))
	fmt.Printf("  最大レスポンス時間: %.3f秒\n", result.Statistics.ResponseTimeStats.Maximum)
	fmt.Printf("  95パーセンタイル: %.3f秒\n\n", result.Statistics.ResponseTimeStats.Percentile95)

	// Top error summary
	if len(result.HTTPErrors.TopErrorURLs) > 0 {
		fmt.Println("エラー頻発URL:")
		count := len(result.HTTPErrors.TopErrorURLs)
		if count > 3 {
			count = 3
		}
		for i := 0; i < count; i++ {
			url := result.HTTPErrors.TopErrorURLs[i]
			if len(url.URL) > 60 {
				fmt.Printf("  %d. %s... (%sエラー)\n", i+1, url.URL[:57], utils.FormatNumber(url.Count))
			} else {
				fmt.Printf("  %d. %s (%sエラー)\n", i+1, url.URL, utils.FormatNumber(url.Count))
			}
		}
		fmt.Println()
	}

	// Recommendations
	printRecommendations(result)
	
	fmt.Printf("📊 詳細レポート: %s\n", reportPath)
}

func printRecommendations(result *analyzer.AnalysisResult) {
	fmt.Println("推奨事項:")
	
	recommendations := []string{}
	
	// Security recommendations
	if len(result.SecurityAnalysis.SuspiciousIPs) > 0 {
		recommendations = append(recommendations, 
			fmt.Sprintf("🔒 疑わしいIP %d件のブロックを検討してください", len(result.SecurityAnalysis.SuspiciousIPs)))
	}
	
	// Performance recommendations
	if result.Statistics.ResponseTimeStats.SlowRequests > 0 {
		recommendations = append(recommendations, 
			fmt.Sprintf("⚡ 遅いリクエスト %d件(3秒超)の調査をお勧めします", result.Statistics.ResponseTimeStats.SlowRequests))
	}
	
	// Error rate recommendations
	if result.Summary.ErrorRate > 5.0 {
		recommendations = append(recommendations, 
			fmt.Sprintf("❗ 高いエラー率 (%.2f%%) - エラー原因の調査が必要です", result.Summary.ErrorRate))
	}
	
	// Security attack recommendations
	if result.SecurityAnalysis.SQLInjectionAttempts > 0 || result.SecurityAnalysis.XSSAttempts > 0 {
		recommendations = append(recommendations, 
			"🛡️  追加のセキュリティ対策 (WAF、レート制限)の実装をお勧めします")
	}
	
	if len(recommendations) == 0 {
		recommendations = append(recommendations, "✅ 重大な問題は検出されませんでした")
	}
	
	for _, rec := range recommendations {
		fmt.Printf("  • %s\n", rec)
	}
	fmt.Println()
}


func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Kinsta Log Analyzer v%s\n", version)
		fmt.Fprintf(os.Stderr, "A tool for analyzing Kinsta Nginx access logs\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s --input /path/to/access.log\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(os.Stderr, "  %s --input /path/to/access.log --config custom.yaml --verbose\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(os.Stderr, "  %s --input /path/to/access.log --output /custom/output/dir\n", filepath.Base(os.Args[0]))
	}
}