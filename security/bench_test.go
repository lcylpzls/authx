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

// BenchmarkGuardConcurrent 测量高并发失败记录与锁定查询。
func BenchmarkGuardConcurrent(b *testing.B) {
	g, err := NewLoginGuard(1000, time.Minute)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = g.RecordFailure("u-1001")
			_ = g.IsLocked("u-1001")
		}
	})
}
