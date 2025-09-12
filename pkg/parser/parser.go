package parser

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type LogEntry struct {
	Domain       string
	ClientIP     string
	Timestamp    time.Time
	Method       string
	URI          string
	Protocol     string
	StatusCode   int
	Referer      string
	UserAgent    string
	RealIP       string
	UpstreamURI  string
	ResponseSize int64
	ResponseTime float64
}

var (
	timestampRegex = regexp.MustCompile(`\[([^\]]+)\]`)
	quotedRegex    = regexp.MustCompile(`"([^"]*)"`)
	numberRegex    = regexp.MustCompile(`\d+\.?\d*`)
)

func ParseLogLine(line string) (*LogEntry, error) {
	if strings.TrimSpace(line) == "" {
		return nil, fmt.Errorf("empty log line")
	}

	parts := strings.Fields(line)
	if len(parts) < 14 {
		return nil, fmt.Errorf("insufficient fields in log line: got %d, expected at least 14", len(parts))
	}

	entry := &LogEntry{}
	
	// Domain
	entry.Domain = parts[0]
	
	// Client IP
	entry.ClientIP = parts[1]
	
	// Timestamp [22/Sep/2021:21:26:10 +0000]
	timestampMatch := timestampRegex.FindStringSubmatch(line)
	if len(timestampMatch) > 1 {
		timestamp, err := time.Parse("02/Jan/2006:15:04:05 -0700", timestampMatch[1])
		if err != nil {
			return nil, fmt.Errorf("failed to parse timestamp: %v", err)
		}
		entry.Timestamp = timestamp
	}

	// Method, URI, Protocol from quoted request string
	quotedMatches := quotedRegex.FindAllStringSubmatch(line, -1)
	if len(quotedMatches) >= 3 {
		// Parse "GET /wp-admin/ HTTP/1.0"
		requestParts := strings.Fields(quotedMatches[0][1])
		if len(requestParts) >= 3 {
			entry.Method = requestParts[0]
			entry.URI = requestParts[1]
			entry.Protocol = requestParts[2]
		}
		
		// Referer (second quoted string, might be "-")
		entry.Referer = quotedMatches[1][1]
		
		// User Agent (third quoted string)
		entry.UserAgent = quotedMatches[2][1]
	}

	// Status Code
	statusIdx := -1
	for i, part := range parts {
		if matched, _ := regexp.MatchString(`^\d{3}$`, part); matched {
			if statusCode, err := strconv.Atoi(part); err == nil {
				entry.StatusCode = statusCode
				statusIdx = i
				break
			}
		}
	}

	// Real IP (after status code)
	if statusIdx >= 0 && statusIdx+2 < len(parts) {
		entry.RealIP = parts[statusIdx+2]
	}

	// Upstream URI (quoted string after real IP)
	upstreamMatch := regexp.MustCompile(`"([^"]*?)"`).FindStringSubmatch(line[strings.LastIndex(line, entry.RealIP)+len(entry.RealIP):])
	if len(upstreamMatch) > 1 {
		entry.UpstreamURI = upstreamMatch[1]
	}

	// Response Size and Response Time (last two numeric values)
	numbers := numberRegex.FindAllString(line, -1)
	if len(numbers) >= 2 {
		// Response Size
		if size, err := strconv.ParseInt(numbers[len(numbers)-2], 10, 64); err == nil {
			entry.ResponseSize = size
		}
		
		// Response Time
		if respTime, err := strconv.ParseFloat(numbers[len(numbers)-1], 64); err == nil {
			entry.ResponseTime = respTime
		}
	}

	return entry, nil
}

func (e *LogEntry) IsError() bool {
	return e.StatusCode >= 400
}

func (e *LogEntry) IsClientError() bool {
	return e.StatusCode >= 400 && e.StatusCode < 500
}

func (e *LogEntry) IsServerError() bool {
	return e.StatusCode >= 500
}

func (e *LogEntry) IsSlowResponse(threshold float64) bool {
	return e.ResponseTime > threshold
}