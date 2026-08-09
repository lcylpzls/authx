package mfa

import (
	"testing"
	"time"
)

// BenchmarkGenerateCode 测量 TOTP 生成耗时。
func BenchmarkGenerateCode(b *testing.B) {
	secret, err := GenerateSecret()
	if err != nil {
		b.Fatal(err)
	}
	at := time.Unix(59, 0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GenerateCode(secret, at)
	}
}

// BenchmarkValidateCode 测量 TOTP 校验耗时。
func BenchmarkValidateCode(b *testing.B) {
	secret, err := GenerateSecret()
	if err != nil {
		b.Fatal(err)
	}
	at := time.Now()
	code, err := GenerateCode(secret, at)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ValidateCode(secret, code, at, 1)
	}
}
