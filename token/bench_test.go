package token

import (
	"testing"
)

// BenchmarkSignHS256 测量 HS256 签发耗时。
func BenchmarkSignHS256(b *testing.B) {
	s, err := NewHS256([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = s.Sign("u-1001")
	}
}

// BenchmarkParseHS256 测量 HS256 校验耗时。
func BenchmarkParseHS256(b *testing.B) {
	s, err := NewHS256([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		b.Fatal(err)
	}
	raw, err := s.Sign("u-1001")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = s.Parse(raw)
	}
}
