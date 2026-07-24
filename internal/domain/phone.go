package domain

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

const MaxPhoneLength = 20

var phonePattern = regexp.MustCompile(`^\+?[0-9\s\-()]+$`)

// ParsePhone validates an optional phone. Empty/whitespace clears to nil.
func ParsePhone(raw string) (*string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}
	if utf8.RuneCountInString(trimmed) > MaxPhoneLength || !phonePattern.MatchString(trimmed) {
		return nil, &ValidationError{Fields: []FieldError{
			{Field: "phone", Message: "invalid phone"},
		}}
	}
	return &trimmed, nil
}
