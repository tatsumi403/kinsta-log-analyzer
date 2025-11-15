package analyzer

import (
	"sort"
)

func (a *Analyzer) generateSummary() Summary {
	errorRate := 0.0
	if a.totalRequests > 0 {
		errorRate = float64(a.errorRequests) / float64(a.totalRequests) * 100
	}

	avgResponseTime := 0.0
	if a.responseTimeCount > 0 {
		avgResponseTime = a.responseTimeSum / float64(a.responseTimeCount)
	}

	return Summary{
		StartTime:       a.startTime,
		EndTime:         a.endTime,
		TotalRequests:   a.totalRequests,
		ErrorRate:       errorRate,
		AvgResponseTime: avgResponseTime,
	}
}

func (a *Analyzer) generateHTTPErrors() HTTPErrors {
	clientErrors := make(map[int]int)
	serverErrors := make(map[int]int)

	for status, count := range a.statusCodes {
		if status >= 400 && status < 500 {
			clientErrors[status] = count
		} else if status >= 500 {
			serverErrors[status] = count
		}
	}

	// Top error URLs
	var urlErrors []URLError
	for url, count := range a.errorURLs {
		urlErrors = append(urlErrors, URLError{
			URL:   url,
			Count: count,
		})
	}

	sort.Slice(urlErrors, func(i, j int) bool {
		return urlErrors[i].Count > urlErrors[j].Count
	})

	// Limit to top N
	if len(urlErrors) > a.config.Output.TopErrorsCount {
		urlErrors = urlErrors[:a.config.Output.TopErrorsCount]
	}

	return HTTPErrors{
		ClientErrors: clientErrors,
		ServerErrors: serverErrors,
		TopErrorURLs: urlErrors,
	}
}

func (a *Analyzer) generateSecurityAnalysis() SecurityAnalysis {
	sqlAttempts := 0
	xssAttempts := 0
	var suspiciousIPs []SuspiciousIP

	for ip, attacks := range a.attacksByIP {
		sqlAttempts += attacks.SQLAttempts
		xssAttempts += attacks.XSSAttempts

		// Consider IP suspicious if it has any attack attempts
		if attacks.SQLAttempts > 0 || attacks.XSSAttempts > 0 {
			score := attacks.SQLAttempts*2 + attacks.XSSAttempts*2 // Weight can be adjusted
			suspiciousIPs = append(suspiciousIPs, SuspiciousIP{
				IP:            ip,
				SQLAttempts:   attacks.SQLAttempts,
				XSSAttempts:   attacks.XSSAttempts,
				TotalRequests: attacks.TotalRequests,
				AttackScore:   score,
			})
		}
	}

	// Sort suspicious IPs by attack score
	sort.Slice(suspiciousIPs, func(i, j int) bool {
		return suspiciousIPs[i].AttackScore > suspiciousIPs[j].AttackScore
	})

	return SecurityAnalysis{
		SQLInjectionAttempts: sqlAttempts,
		XSSAttempts:         xssAttempts,
		SuspiciousIPs:       suspiciousIPs,
		AttacksByIP:         a.attacksByIP,
	}
}

func (a *Analyzer) generateStatistics() Statistics {
	// Top IPs
	var ipCounts []IPCount
	for ip, count := range a.ipCounts {
		ipCounts = append(ipCounts, IPCount{
			IP:    ip,
			Count: count,
		})
	}

	sort.Slice(ipCounts, func(i, j int) bool {
		return ipCounts[i].Count > ipCounts[j].Count
	})

	if len(ipCounts) > a.config.Output.TopIPsCount {
		ipCounts = ipCounts[:a.config.Output.TopIPsCount]
	}

	// Response time statistics
	responseTimeStats := a.calculateResponseTimeStats()

	return Statistics{
		HourlyPattern:     a.hourlyPattern,
		TopIPs:           ipCounts,
		ResponseTimeStats: responseTimeStats,
		StatusCodes:      a.statusCodes,
	}
}

func (a *Analyzer) generateUserAgentAnalysis() UserAgentAnalysis {
	// Find suspicious user agents (not crawlers or attack tools)
	var suspiciousUAs []UACount
	
	for ua, count := range a.userAgents {
		// Skip known crawlers and attack tools
		if !a.config.IsCrawler(ua) && !a.config.IsAttackTool(ua) {
			// Consider suspicious if very few requests or unusual patterns
			if count < 5 || len(ua) < 10 || len(ua) > 200 {
				suspiciousUAs = append(suspiciousUAs, UACount{
					UserAgent: ua,
					Count:     count,
				})
			}
		}
	}

	sort.Slice(suspiciousUAs, func(i, j int) bool {
		return suspiciousUAs[i].Count > suspiciousUAs[j].Count
	})

	// Limit results
	if len(suspiciousUAs) > 20 {
		suspiciousUAs = suspiciousUAs[:20]
	}

	return UserAgentAnalysis{
		Crawlers:      a.crawlers,
		AttackTools:   a.attackTools,
		SuspiciousUAs: suspiciousUAs,
	}
}

func (a *Analyzer) calculateResponseTimeStats() ResponseTimeStats {
	if a.responseTimeCount == 0 {
		return ResponseTimeStats{}
	}

	// Calculate average from pre-computed sum
	average := a.responseTimeSum / float64(a.responseTimeCount)

	// Calculate 95th percentile from sample
	percentile95 := 0.0
	if len(a.responseTimeSample) > 0 {
		// Sort the sample for percentile calculation
		sortedSample := make([]float64, len(a.responseTimeSample))
		copy(sortedSample, a.responseTimeSample)
		sort.Float64s(sortedSample)

		// Calculate 95th percentile from sample
		p95Index := int(0.95 * float64(len(sortedSample)))
		if p95Index >= len(sortedSample) {
			p95Index = len(sortedSample) - 1
		}
		percentile95 = sortedSample[p95Index]
	}

	return ResponseTimeStats{
		Average:      average,
		Maximum:      a.responseTimeMax,
		Percentile95: percentile95,
		SlowRequests: a.slowRequestCount,
	}
}