// Package utils provides common utility functions used across the application.
package utils

import (
	"fmt"
	"time"
)

// JST is the Asia/Tokyo timezone (UTC+9), used for all human-facing
// timestamps and hourly bucket boundaries in reports.
var JST = time.FixedZone("JST", 9*3600)

// FormatNumber formats an integer with comma separators for thousands.
// Example: 1234567 -> "1,234,567"
func FormatNumber(num int) string {
	if num < 1000 {
		return fmt.Sprintf("%d", num)
	}
	return addCommas(num)
}

// addCommas adds comma separators to a number string.
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
