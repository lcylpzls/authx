package middleware

import (
	"testing"
)

// BenchmarkValidateCSRFToken 测量 CSRF 令牌常量时间比较耗时。
func BenchmarkValidateCSRFToken(b *testing.B) {
	token, err := GenerateCSRFToken()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateCSRFToken(token, token)
	}
}
