package token

import (
	"context"
	testx "github.com/lcylpzls/testx"
	"testing"
	"time"
)

// BenchmarkSignHS256 测量 HS256 签发耗时。
func BenchmarkSignHS256(b *testing.B) {
	s, err := NewHS256([]byte("0123456789abcdef0123456789abcdef"))
	testx.RequireNoError(b, err)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = s.Sign("u-1001")
	}
}

// BenchmarkParseHS256 测量 HS256 校验耗时。
func BenchmarkParseHS256(b *testing.B) {
	s, err := NewHS256([]byte("0123456789abcdef0123456789abcdef"))
	testx.RequireNoError(b, err)

	raw, err := s.Sign("u-1001")
	testx.RequireNoError(b, err)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = s.Parse(raw)
	}
}

// BenchmarkRefreshStoreConcurrent 测量高并发刷新令牌读写。
func BenchmarkRefreshStoreConcurrent(b *testing.B) {
	store := NewMemoryRefreshStore(nil)
	ctx := context.Background()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			raw, err := IssueRefreshToken(ctx, store, time.Hour)
			if err != nil {
				continue
			}
			_, _ = ValidateRefreshToken(ctx, store, raw)
			_ = ConsumeRefreshToken(ctx, store, raw)
		}
	})
}
