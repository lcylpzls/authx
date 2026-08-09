package middleware

import (
	"testing"
)

// FuzzCSRF 模糊测试 CSRF 令牌比较与 Bearer 提取，确保任意输入不 panic。
func FuzzCSRF(f *testing.F) {
	f.Add("abc", "abc")
	f.Add("", "x")
	f.Add("Bearer token", "abc")
	f.Fuzz(func(t *testing.T, cookie, header string) {
		_ = ValidateCSRFToken(cookie, header)
		_, _ = bearerToken(cookie)
	})
}
