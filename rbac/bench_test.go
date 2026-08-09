package rbac

import (
	"testing"
)

// BenchmarkHasPermission 测量含继承链的权限判断耗时。
func BenchmarkHasPermission(b *testing.B) {
	r := New()
	_ = r.AddRole("base", "order:read", "order:write")
	_ = r.AddRole("ops")
	_ = r.AddRole("admin")
	_ = r.Inherit("ops", "base")
	_ = r.Inherit("admin", "ops")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.HasPermission("admin", "order:read")
	}
}
