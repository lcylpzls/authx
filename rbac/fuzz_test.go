package rbac

import (
	"strings"
	"testing"
)

// FuzzRBAC 模糊测试 RBAC 操作序列，确保任意输入不 panic、不死循环。
func FuzzRBAC(f *testing.F) {
	f.Add([]byte("role:a;role:b;perm:a:r;perm:b:w;inherit:b:a;check:b:r;check:a:w"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			t.Skip("输入过大")
		}
		r := NewWithLimits(128, 8)
		for _, op := range strings.Split(string(data), ";") {
			switch {
			case strings.HasPrefix(op, "role:"):
				_ = r.AddRole(strings.TrimPrefix(op, "role:"))
			case strings.HasPrefix(op, "perm:"):
				seg := strings.SplitN(strings.TrimPrefix(op, "perm:"), ":", 2)
				if len(seg) == 2 {
					_ = r.AddPermission(seg[0], seg[1])
				}
			case strings.HasPrefix(op, "inherit:"):
				seg := strings.SplitN(strings.TrimPrefix(op, "inherit:"), ":", 2)
				if len(seg) == 2 {
					_ = r.Inherit(seg[0], seg[1])
				}
			case strings.HasPrefix(op, "check:"):
				seg := strings.SplitN(strings.TrimPrefix(op, "check:"), ":", 2)
				if len(seg) == 2 {
					_ = r.HasPermission(seg[0], seg[1])
				}
			}
		}
		_ = r.HasAnyPermission(nil, "x")
		_ = r.PermissionsOf("a")
	})
}
