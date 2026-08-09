package security

import (
	"testing"
	"time"
)

// BenchmarkRecordFailure 测量登录失败记录耗时。
func BenchmarkRecordFailure(b *testing.B) {
	g, err := NewLoginGuard(100, time.Minute)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = g.RecordFailure("u-1001")
	}
}
