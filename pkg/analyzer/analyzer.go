package analyzer

import (
	"bufio"
	"fmt"
	"os"
	"sync"
	"time"

	"kinsta-log-analyzer/pkg/config"
	"kinsta-log-analyzer/pkg/parser"
)

type AnalysisResult struct {
	Summary           Summary
	HTTPErrors        HTTPErrors
	SecurityAnalysis  SecurityAnalysis
	Statistics        Statistics
	UserAgentAnalysis UserAgentAnalysis
}

type Summary struct {
	StartTime        time.Time
	EndTime          time.Time
	TotalRequests    int
	ErrorRate        float64
	AvgResponseTime  float64
}

type HTTPErrors struct {
	ClientErrors map[int]int // 4xx errors: status code -> count
	ServerErrors map[int]int // 5xx errors: status code -> count
	TopErrorURLs []URLError
}

type SecurityAnalysis struct {
	SQLInjectionAttempts int
	XSSAttempts         int
	SuspiciousIPs       []SuspiciousIP
	AttacksByIP         map[string]*IPAttacks
}

type Statistics struct {
	HourlyPattern    [24]int
	TopIPs           []IPCount
	ResponseTimeStats ResponseTimeStats
	StatusCodes      map[int]int
}

type UserAgentAnalysis struct {
	Crawlers        map[string]int
	AttackTools     map[string]int
	SuspiciousUAs   []UACount
}

type URLError struct {
	URL   string
	Count int
}

type SuspiciousIP struct {
	IP               string
	SQLAttempts      int
	XSSAttempts      int
	TotalRequests    int
	AttackScore      int
}

type IPAttacks struct {
	SQLAttempts   int
	XSSAttempts   int
	TotalRequests int
}

type IPCount struct {
	IP    string
	Count int
}

type UACount struct {
	UserAgent string
	Count     int
}

type ResponseTimeStats struct {
	Average     float64
	Maximum     float64
	Percentile95 float64
	SlowRequests int
}

type Analyzer struct {
	config         *config.Config
	mutex          sync.Mutex
	totalRequests  int
	errorRequests  int
	responseTime   []float64
	ipCounts       map[string]int
	errorURLs      map[string]int
	hourlyPattern  [24]int
	statusCodes    map[int]int
	userAgents     map[string]int
	attacksByIP    map[string]*IPAttacks
	crawlers       map[string]int
	attackTools    map[string]int
	startTime      time.Time
	endTime        time.Time
}

func NewAnalyzer(cfg *config.Config) *Analyzer {
	return &Analyzer{
		config:      cfg,
		ipCounts:    make(map[string]int),
		errorURLs:   make(map[string]int),
		statusCodes: make(map[int]int),
		userAgents:  make(map[string]int),
		attacksByIP: make(map[string]*IPAttacks),
		crawlers:    make(map[string]int),
		attackTools: make(map[string]int),
	}
}

func (a *Analyzer) AnalyzeFile(filePath string) (*AnalysisResult, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	
	for scanner.Scan() {
		line := scanner.Text()
		entry, err := parser.ParseLogLine(line)
		if err != nil {
			// Skip invalid lines but continue processing
			continue
		}

		a.processEntry(entry)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}

	return a.generateResult(), nil
}

func (a *Analyzer) processEntry(entry *parser.LogEntry) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	a.totalRequests++

	// Track time range
	if a.totalRequests == 1 {
		a.startTime = entry.Timestamp
		a.endTime = entry.Timestamp
	} else {
		if entry.Timestamp.Before(a.startTime) {
			a.startTime = entry.Timestamp
		}
		if entry.Timestamp.After(a.endTime) {
			a.endTime = entry.Timestamp
		}
	}

	// Response time tracking
	a.responseTime = append(a.responseTime, entry.ResponseTime)

	// IP counting
	a.ipCounts[entry.ClientIP]++

	// Hourly pattern
	hour := entry.Timestamp.Hour()
	a.hourlyPattern[hour]++

	// Status codes
	a.statusCodes[entry.StatusCode]++

	// User agent analysis
	a.userAgents[entry.UserAgent]++

	// Error analysis
	if entry.IsError() {
		a.errorRequests++
		a.errorURLs[entry.URI]++
	}

	// Initialize IP attacks if not exists
	if a.attacksByIP[entry.ClientIP] == nil {
		a.attacksByIP[entry.ClientIP] = &IPAttacks{}
	}
	a.attacksByIP[entry.ClientIP].TotalRequests++

	// Security analysis
	if a.config.IsSQLInjectionAttempt(entry.URI, entry.UserAgent) {
		a.attacksByIP[entry.ClientIP].SQLAttempts++
	}

	if a.config.IsXSSAttempt(entry.URI, entry.UserAgent) {
		a.attacksByIP[entry.ClientIP].XSSAttempts++
	}

	// Crawler detection
	if a.config.IsCrawler(entry.UserAgent) {
		a.crawlers[entry.UserAgent]++
	}

	// Attack tool detection
	if a.config.IsAttackTool(entry.UserAgent) {
		a.attackTools[entry.UserAgent]++
	}
}

func (a *Analyzer) generateResult() *AnalysisResult {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	return &AnalysisResult{
		Summary:           a.generateSummary(),
		HTTPErrors:        a.generateHTTPErrors(),
		SecurityAnalysis:  a.generateSecurityAnalysis(),
		Statistics:        a.generateStatistics(),
		UserAgentAnalysis: a.generateUserAgentAnalysis(),
	}
}