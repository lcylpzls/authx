package mfa

import (
	"testing"
	"time"
)

// FuzzTOTP 模糊测试 TOTP 生成与校验，确保任意输入不 panic。
func FuzzTOTP(f *testing.F) {
	f.Add("GEZDGNBVGY3TQOJQ", "287082", int64(59), uint(1), uint8(0), int64(30*time.Second))
	f.Fuzz(func(t *testing.T, secret, code string, at int64, skew uint, alg uint8, period int64) {
		if len(secret) > 1024 || len(code) > 64 {
			t.Skip("输入过大")
		}
		cfg := TOTPConfig{Algorithm: Algorithm(alg), Digits: 6, Period: time.Duration(period)}
		_ = cfg.Validate()
		_, _ = GenerateCodeWithConfig(secret, time.Unix(at, 0), cfg)
		_, _ = ValidateCodeWithConfig(secret, code, time.Unix(at, 0), skew, cfg)
	})
}
