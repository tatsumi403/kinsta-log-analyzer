package parser

import (
	"testing"
	"time"
)

func TestParseLogLine(t *testing.T) {
	// Sample log line from Kinsta
	logLine := `kinstahelptesting.kinsta.cloud 98.43.13.94 [22/Sep/2021:21:26:10 +0000] "GET /wp-admin/ HTTP/1.0" 302 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:92.0) Gecko/20100101 Firefox/92.0" 98.43.13.94 "/wp-admin/index.php" - - 472 0.562 0.560`

	entry, err := ParseLogLine(logLine)
	if err != nil {
		t.Fatalf("Failed to parse log line: %v", err)
	}

	// Test basic fields
	if entry.Domain != "kinstahelptesting.kinsta.cloud" {
		t.Errorf("Expected domain 'kinstahelptesting.kinsta.cloud', got '%s'", entry.Domain)
	}

	if entry.ClientIP != "98.43.13.94" {
		t.Errorf("Expected client IP '98.43.13.94', got '%s'", entry.ClientIP)
	}

	if entry.Method != "GET" {
		t.Errorf("Expected method 'GET', got '%s'", entry.Method)
	}

	if entry.URI != "/wp-admin/" {
		t.Errorf("Expected URI '/wp-admin/', got '%s'", entry.URI)
	}

	if entry.StatusCode != 302 {
		t.Errorf("Expected status code 302, got %d", entry.StatusCode)
	}

	if entry.ResponseTime != 0.560 {
		t.Errorf("Expected response time 0.560, got %f", entry.ResponseTime)
	}

	// Test timestamp parsing
	expectedTime, _ := time.Parse("02/Jan/2006:15:04:05 -0700", "22/Sep/2021:21:26:10 +0000")
	if !entry.Timestamp.Equal(expectedTime) {
		t.Errorf("Expected timestamp %v, got %v", expectedTime, entry.Timestamp)
	}
}

func TestParseLogLineErrors(t *testing.T) {
	testCases := []struct {
		name    string
		logLine string
	}{
		{"Empty line", ""},
		{"Insufficient fields", "domain ip"},
		{"Invalid format", "this is not a valid log line"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseLogLine(tc.logLine)
			if err == nil {
				t.Errorf("Expected error for invalid log line: %s", tc.logLine)
			}
		})
	}
}

func TestLogEntryMethods(t *testing.T) {
	entry := &LogEntry{
		StatusCode:   404,
		ResponseTime: 5.0,
	}

	if !entry.IsError() {
		t.Error("Expected IsError() to return true for 404")
	}

	if !entry.IsClientError() {
		t.Error("Expected IsClientError() to return true for 404")
	}

	if entry.IsServerError() {
		t.Error("Expected IsServerError() to return false for 404")
	}

	if !entry.IsSlowResponse(3.0) {
		t.Error("Expected IsSlowResponse(3.0) to return true for 5.0s response time")
	}

	// Test server error
	entry.StatusCode = 500
	if !entry.IsServerError() {
		t.Error("Expected IsServerError() to return true for 500")
	}

	if entry.IsClientError() {
		t.Error("Expected IsClientError() to return false for 500")
	}
}