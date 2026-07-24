package domain

import (
	"strings"
	"unicode/utf8"
)

const (
	MinPersonNameLength = 2
	MaxPersonNameLength = 20
)

// PersonName is a trimmed first or last name.
type PersonName struct {
	value string
}

func ParsePersonName(raw string) (PersonName, error) {
	trimmed := strings.TrimSpace(raw)
	n := utf8.RuneCountInString(trimmed)
	if n < MinPersonNameLength || n > MaxPersonNameLength {
		return PersonName{}, &ValidationError{Fields: []FieldError{
			{Field: "name", Message: "name must be 2-20 characters"},
		}}
	}
	return PersonName{value: trimmed}, nil
}

func ParsePersonNameField(raw, field string) (PersonName, error) {
	trimmed := strings.TrimSpace(raw)
	n := utf8.RuneCountInString(trimmed)
	if n < MinPersonNameLength || n > MaxPersonNameLength {
		return PersonName{}, &ValidationError{Fields: []FieldError{
			{Field: field, Message: field + " must be 2-20 characters"},
		}}
	}
	return PersonName{value: trimmed}, nil
}

func (n PersonName) String() string {
	return n.value
}

func (n PersonName) IsZero() bool {
	return n.value == ""
}
