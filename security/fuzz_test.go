package security

import (
	"strings"
	"testing"
	"time"
)

// FuzzLoginGuard 模糊测试登录守卫操作序列，确保任意输入不 panic。
func FuzzLoginGuard(f *testing.F) {
	f.Add([]byte("fail:a;fail:a;fail:a;lock;reset;cleanup"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			t.Skip("输入过大")
		}
		g, err := NewLoginGuard(3, time.Minute, WithFailureWindow(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		for _, op := range strings.Split(string(data), ";") {
			switch {
			case strings.HasPrefix(op, "fail:"):
				_ = g.RecordFailure(strings.TrimPrefix(op, "fail:"))
			case op == "lock":
				_ = g.IsLocked("x")
			case op == "reset":
				g.Reset("x")
			case op == "cleanup":
				_ = g.Cleanup()
			}
		}
	})
}
