package token

import (
	testx "github.com/lcylpzls/testx"
	"testing"
)

// FuzzParse 保证任意输入下 Parse 不 panic。
func FuzzParse(f *testing.F) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	s, err := NewHS256(secret)
	testx.RequireNoError(f, err)

	raw, err := s.Sign("u-1")
	testx.RequireNoError(f, err)

	f.Add(raw)
	f.Add("")
	f.Add("not-a-jwt")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1LTEifQ.invalid")
	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = s.Parse(raw)
	})
}
