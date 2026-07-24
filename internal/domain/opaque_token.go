package domain

import (
	"regexp"
	"unicode/utf8"
)

const OpaqueTokenLength = 64

var opaqueTokenPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// OpaqueToken is a 64-char hex token (verification, reset, refresh).
type OpaqueToken struct {
	value string
}

func ParseOpaqueToken(raw string) (OpaqueToken, error) {
	if utf8.RuneCountInString(raw) != OpaqueTokenLength || !opaqueTokenPattern.MatchString(raw) {
		return OpaqueToken{}, ErrInvalidContent
	}
	return OpaqueToken{value: raw}, nil
}

// NewOpaqueToken trusts a freshly generated 64-hex string (e.g. from crypto/rand).
func NewOpaqueToken(raw string) OpaqueToken {
	return OpaqueToken{value: raw}
}

func (t OpaqueToken) String() string {
	return t.value
}

func (t OpaqueToken) IsZero() bool {
	return t.value == ""
}

func (t OpaqueToken) Equal(other string) bool {
	return t.value != "" && t.value == other
}
