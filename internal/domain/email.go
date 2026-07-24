package domain

import (
	"database/sql/driver"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const MaxEmailLength = 180

// Email is a normalized, validated e-mail address.
type Email struct {
	value string
}

// ParseEmail trims whitespace, lowercases, and validates the address.
func ParseEmail(raw string) (Email, error) {
	normalized := normalizeEmail(raw)
	if normalized == "" || utf8.RuneCountInString(normalized) > MaxEmailLength {
		return Email{}, fmt.Errorf("%w: invalid email", ErrInvalidContent)
	}
	at := strings.IndexByte(normalized, '@')
	if at <= 0 || at == len(normalized)-1 || strings.Contains(normalized[at+1:], "@") {
		return Email{}, fmt.Errorf("%w: invalid email", ErrInvalidContent)
	}
	return Email{value: normalized}, nil
}

// MustParseEmail panics on invalid input. Intended for trusted values (e.g. from DB).
func MustParseEmail(raw string) Email {
	email, err := ParseEmail(raw)
	if err != nil {
		panic(err)
	}
	return email
}

func (e Email) String() string {
	return e.value
}

func (e Email) IsZero() bool {
	return e.value == ""
}

func (e Email) MarshalText() ([]byte, error) {
	return []byte(e.value), nil
}

func (e *Email) UnmarshalText(text []byte) error {
	parsed, err := ParseEmail(string(text))
	if err != nil {
		return err
	}
	*e = parsed
	return nil
}

func (e Email) Value() (driver.Value, error) {
	if e.value == "" {
		return nil, nil
	}
	return e.value, nil
}

func (e *Email) Scan(src any) error {
	if src == nil {
		*e = Email{}
		return nil
	}
	var raw string
	switch v := src.(type) {
	case string:
		raw = v
	case []byte:
		raw = string(v)
	default:
		return fmt.Errorf("cannot scan %T into Email", src)
	}
	parsed, err := ParseEmail(raw)
	if err != nil {
		return err
	}
	*e = parsed
	return nil
}

func normalizeEmail(email string) string {
	email = strings.TrimSpace(email)
	email = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, email)
	return strings.ToLower(email)
}
