package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v2"
)

type Config struct {
	Thresholds Thresholds `yaml:"thresholds"`
	Security   Security   `yaml:"security"`
	Output     Output     `yaml:"output"`
}

type Thresholds struct {
	ErrorRateWarning  float64 `yaml:"error_rate_warning"`
	SlowRequestTime   float64 `yaml:"slow_request_time"`
}

type Security struct {
	SQLInjectionPatterns []string `yaml:"sql_injection_patterns"`
	XSSPatterns          []string `yaml:"xss_patterns"`
	CrawlerUserAgents    []string `yaml:"crawler_user_agents"`
	AttackToolPatterns   []string `yaml:"attack_tool_patterns"`
}

type Output struct {
	TopIPsCount      int    `yaml:"top_ips_count"`
	TopErrorsCount   int    `yaml:"top_errors_count"`
	ReportFormat     string `yaml:"report_format"`
	OutputDirectory  string `yaml:"output_directory"`
}

func LoadConfig(configPath string) (*Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	// Convert patterns to lowercase for case-insensitive matching
	config.Security.SQLInjectionPatterns = toLowerSlice(config.Security.SQLInjectionPatterns)
	config.Security.XSSPatterns = toLowerSlice(config.Security.XSSPatterns)
	config.Security.CrawlerUserAgents = toLowerSlice(config.Security.CrawlerUserAgents)
	config.Security.AttackToolPatterns = toLowerSlice(config.Security.AttackToolPatterns)

	return &config, nil
}

func toLowerSlice(slice []string) []string {
	result := make([]string, len(slice))
	for i, s := range slice {
		result[i] = strings.ToLower(s)
	}
	return result
}

func (c *Config) IsSQLInjectionAttempt(uri, userAgent string) bool {
	combined := strings.ToLower(uri + " " + userAgent)
	for _, pattern := range c.Security.SQLInjectionPatterns {
		if strings.Contains(combined, pattern) {
			return true
		}
	}
	return false
}

func (c *Config) IsXSSAttempt(uri, userAgent string) bool {
	combined := strings.ToLower(uri + " " + userAgent)
	for _, pattern := range c.Security.XSSPatterns {
		if strings.Contains(combined, pattern) {
			return true
		}
	}
	return false
}

func (c *Config) IsCrawler(userAgent string) bool {
	userAgentLower := strings.ToLower(userAgent)
	for _, crawler := range c.Security.CrawlerUserAgents {
		if strings.Contains(userAgentLower, crawler) {
			return true
		}
	}
	return false
}

func (c *Config) IsAttackTool(userAgent string) bool {
	userAgentLower := strings.ToLower(userAgent)
	for _, tool := range c.Security.AttackToolPatterns {
		if strings.Contains(userAgentLower, tool) {
			return true
		}
	}
	return false
}