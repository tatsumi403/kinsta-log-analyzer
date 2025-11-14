package utils

import "testing"

func TestFormatNumber(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected string
	}{
		{"small number", 42, "42"},
		{"hundreds", 999, "999"},
		{"thousands", 1000, "1,000"},
		{"ten thousands", 12345, "12,345"},
		{"millions", 1234567, "1,234,567"},
		{"zero", 0, "0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatNumber(tt.input)
			if result != tt.expected {
				t.Errorf("FormatNumber(%d) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}
