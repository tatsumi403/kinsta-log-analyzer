package analyzer

import (
	"fmt"
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
		ClientErrors:      clientErrors,
		ServerErrors:      serverErrors,
		TopErrorURLs:      urlErrors,
		ErrorURLsByStatus: a.generateErrorURLsByStatus(),
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

	errorProneIPs := a.generateErrorProneIPs()
	burstIPs := a.generateBurstIPs()

	return SecurityAnalysis{
		SQLInjectionAttempts: sqlAttempts,
		XSSAttempts:         xssAttempts,
		SuspiciousIPs:       suspiciousIPs,
		AttacksByIP:         a.attacksByIP,
		ErrorProneIPs:       errorProneIPs,
		BurstIPs:            burstIPs,
		ErrorSuspiciousIPs:  mergeErrorSuspiciousIPs(errorProneIPs, burstIPs),
	}
}

// mergeErrorSuspiciousIPs combines high-error-rate IPs and burst IPs into a
// single list. IPs flagged by both criteria appear first (more suspicious),
// then by error rate desc.
func mergeErrorSuspiciousIPs(errorProneIPs []IPErrorRate, burstIPs []BurstIP) []ErrorSuspiciousIP {
	byIP := make(map[string]*ErrorSuspiciousIP)

	for _, e := range errorProneIPs {
		byIP[e.IP] = &ErrorSuspiciousIP{
			IP:            e.IP,
			TotalRequests: e.TotalRequests,
			ErrorCount:    e.ErrorCount,
			ErrorRate:     e.ErrorRate,
			Reasons:       []string{"高エラー率"},
		}
	}

	for _, b := range burstIPs {
		if existing, ok := byIP[b.IP]; ok {
			existing.BurstCount = b.BurstCount
			existing.MaxBurst = b.MaxBurst
			existing.Reasons = append(existing.Reasons, "バースト検出")
		} else {
			byIP[b.IP] = &ErrorSuspiciousIP{
				IP:         b.IP,
				BurstCount: b.BurstCount,
				MaxBurst:   b.MaxBurst,
				Reasons:    []string{"バースト検出"},
			}
		}
	}

	result := make([]ErrorSuspiciousIP, 0, len(byIP))
	for _, v := range byIP {
		result = append(result, *v)
	}

	sort.Slice(result, func(i, j int) bool {
		// 両方の観点に該当するIPを優先
		if len(result[i].Reasons) != len(result[j].Reasons) {
			return len(result[i].Reasons) > len(result[j].Reasons)
		}
		// 次にエラー率
		if result[i].ErrorRate != result[j].ErrorRate {
			return result[i].ErrorRate > result[j].ErrorRate
		}
		// 最後に最大バースト
		return result[i].MaxBurst > result[j].MaxBurst
	})

	if len(result) > 10 {
		result = result[:10]
	}
	return result
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
		HourlyPattern:      a.hourlyPattern,
		HourlyClientErrors: a.hourlyClientErrors,
		HourlyServerErrors: a.hourlyServerErrors,
		TopIPs:             ipCounts,
		ResponseTimeStats:  responseTimeStats,
		StatusCodes:        a.statusCodes,
		SlowURLs:           a.generateSlowURLs(),
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
		ErrorProneUAs: a.generateErrorProneUAs(),
	}
}

// generateErrorProneUAs returns UAs sorted by error rate (descending).
// Only UAs with at least MinRequestsForErrorRate total requests are considered,
// to avoid noise from one-off requests.
func (a *Analyzer) generateErrorProneUAs() []UAErrorRate {
	minReq := a.config.Thresholds.MinRequestsForErrorRate
	var result []UAErrorRate
	for ua, total := range a.userAgents {
		if total < minReq {
			continue
		}
		errs := a.errorsByUA[ua]
		if errs == 0 {
			continue
		}
		result = append(result, UAErrorRate{
			UserAgent:     ua,
			TotalRequests: total,
			ErrorCount:    errs,
			ErrorRate:     float64(errs) / float64(total) * 100,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ErrorRate > result[j].ErrorRate
	})
	if len(result) > 10 {
		result = result[:10]
	}
	return result
}

// generateErrorProneIPs returns IPs sorted by error rate (descending).
// Only IPs with at least MinRequestsForErrorRate total requests are considered.
func (a *Analyzer) generateErrorProneIPs() []IPErrorRate {
	minReq := a.config.Thresholds.MinRequestsForErrorRate
	var result []IPErrorRate
	for ip, attacks := range a.attacksByIP {
		if attacks.TotalRequests < minReq {
			continue
		}
		if attacks.ErrorCount == 0 {
			continue
		}
		result = append(result, IPErrorRate{
			IP:            ip,
			TotalRequests: attacks.TotalRequests,
			ErrorCount:    attacks.ErrorCount,
			ErrorRate:     float64(attacks.ErrorCount) / float64(attacks.TotalRequests) * 100,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ErrorRate > result[j].ErrorRate
	})
	if len(result) > 10 {
		result = result[:10]
	}
	return result
}

// generateErrorURLsByStatus returns Top 10 URLs per target status code (404, 500, 502, 503, 504).
// Codes with no recorded URLs are omitted from the returned map.
func (a *Analyzer) generateErrorURLsByStatus() map[int][]URLError {
	targetCodes := []int{404, 500, 502, 503, 504}
	result := make(map[int][]URLError)
	for _, code := range targetCodes {
		urls, ok := a.errorURLsByStatus[code]
		if !ok || len(urls) == 0 {
			continue
		}
		var list []URLError
		for u, c := range urls {
			list = append(list, URLError{URL: u, Count: c})
		}
		sort.Slice(list, func(i, j int) bool {
			return list[i].Count > list[j].Count
		})
		if len(list) > 10 {
			list = list[:10]
		}
		result[code] = list
	}
	return result
}

// generateBurstIPs scans each IP's error timestamps with a sliding window.
// For every error, count errors within the next BurstWindowSeconds; if it exceeds
// BurstThreshold, count one burst. Returns Top 10 IPs by burst count.
// Timestamps are sorted because reservoir-like ordering is not guaranteed.
func (a *Analyzer) generateBurstIPs() []BurstIP {
	windowSec := a.config.Thresholds.BurstWindowSeconds
	threshold := a.config.Thresholds.BurstThreshold
	if windowSec <= 0 || threshold <= 0 {
		return nil
	}

	var result []BurstIP
	for ip, timestamps := range a.errorTimestampsByIP {
		if len(timestamps) < threshold {
			continue
		}
		sorted := make([]int64, len(timestamps))
		for i, t := range timestamps {
			sorted[i] = t.Unix()
		}
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

		burstCount := 0
		maxBurst := 0
		windowDelta := int64(windowSec)
		right := 0
		for left := 0; left < len(sorted); left++ {
			if right < left {
				right = left
			}
			for right < len(sorted) && sorted[right]-sorted[left] <= windowDelta {
				right++
			}
			count := right - left
			if count >= threshold {
				burstCount++
				if count > maxBurst {
					maxBurst = count
				}
			}
		}

		if burstCount > 0 {
			result = append(result, BurstIP{
				IP:         ip,
				BurstCount: burstCount,
				MaxBurst:   maxBurst,
				Window:     fmt.Sprintf("%ds", windowSec),
			})
		}
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].MaxBurst != result[j].MaxBurst {
			return result[i].MaxBurst > result[j].MaxBurst
		}
		return result[i].BurstCount > result[j].BurstCount
	})
	if len(result) > 10 {
		result = result[:10]
	}
	return result
}

// generateSlowURLs returns Top 10 URLs by slow-request count.
func (a *Analyzer) generateSlowURLs() []URLError {
	var result []URLError
	for u, c := range a.slowURLs {
		result = append(result, URLError{URL: u, Count: c})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})
	if len(result) > 10 {
		result = result[:10]
	}
	return result
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