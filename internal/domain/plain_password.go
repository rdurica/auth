package domain

import "unicode/utf8"

const (
	MinPasswordLength = 8
	MaxPasswordLength = 50
)

// PlainPassword is a validated plaintext password (never persist).
type PlainPassword struct {
	value string
}

func ParsePlainPassword(raw string) (PlainPassword, error) {
	return ParsePlainPasswordField(raw, "password")
}

func ParsePlainPasswordField(raw, field string) (PlainPassword, error) {
	n := utf8.RuneCountInString(raw)
	if n < MinPasswordLength || n > MaxPasswordLength {
		return PlainPassword{}, &ValidationError{Fields: []FieldError{
			{Field: field, Message: "password must be 8-50 characters"},
		}}
	}
	return PlainPassword{value: raw}, nil
}

func (p PlainPassword) String() string {
	return p.value
}
