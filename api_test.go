package authx_test

import (
	"testing"
	"time"

	"github.com/lcylpzls/authx"
)

// TestPublicAPI 黑盒冒烟测试：覆盖根包转发函数、类型别名与常量。
func TestPublicAPI(t *testing.T) {
	cfg := authx.DefaultPasswordConfig()
	if cfg.Memory == 0 || cfg.KeyLength == 0 {
		t.Fatal("DefaultPasswordConfig 返回零值配置")
	}

	h := authx.StartCleanup(time.Hour, func() int { return 0 })
	if h == nil {
		t.Fatal("StartCleanup 返回 nil")
	}
	h.Stop()

	_ = authx.CodePasswordHashInvalid
	_ = authx.CodeTokenInvalid
	_ = authx.CodeForbidden
	_ = authx.CodeCSRFMismatch
	_ = authx.CodeSessionNotFound
	_ = authx.CodeMFAInvalid
	_ = authx.CodeOAuth2Invalid
	_ = authx.CodeRBACRoleNotFound
	_ = authx.CodeAuditQueueFull
	_ = authx.ErrPasswordMismatch
	_ = authx.ErrTokenExpired
	_ = authx.ErrForbidden
	_ = authx.ErrCSRFMismatch
	_ = authx.ErrSessionNotFound
	_ = authx.ErrMFAInvalid
	_ = authx.ErrOAuth2Invalid
	_ = authx.ErrRoleNotFound

	var _ authx.PasswordConfig
	var _ authx.AuthEvent
	var _ authx.EventHook
	var _ authx.TraceAttr
	var _ authx.TraceHook
}
