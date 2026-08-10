package password

import (
	testx "github.com/lcylpzls/testx"
	"testing"

	"github.com/lcylpzls/authx"
)

// BenchmarkHash 测量 Argon2id 哈希耗时（OWASP 默认参数）。
func BenchmarkHash(b *testing.B) {
	cfg := authx.DefaultPasswordConfig()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = Hash("password123", cfg)
	}
}

// BenchmarkVerify 测量哈希校验耗时（先预生成哈希）。
func BenchmarkVerify(b *testing.B) {
	cfg := authx.DefaultPasswordConfig()
	h, err := Hash("password123", cfg)
	testx.RequireNoError(b, err)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Verify(h, "password123")
	}
}
