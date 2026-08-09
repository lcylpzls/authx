package authx

import (
	"testing"

	"github.com/lcylpzls/errx"
)

// TestDefaultPasswordConfig 覆盖默认参数。
func TestDefaultPasswordConfig(t *testing.T) {
	cfg := DefaultPasswordConfig()
	if cfg.Memory != 19456 || cfg.Iterations != 2 || cfg.Parallelism != 1 ||
		cfg.KeyLength != 32 || cfg.SaltLength != 16 {
		t.Fatalf("默认参数不符：%+v", cfg)
	}
}

// TestValidate 覆盖合法与全部分支的非法参数。
func TestValidate(t *testing.T) {
	if err := DefaultPasswordConfig().Validate(); err != nil {
		t.Fatalf("默认配置应合法：%v", err)
	}
	bad := []PasswordConfig{
		{Memory: 8191, Iterations: 2, Parallelism: 1, KeyLength: 32, SaltLength: 16},
		{Memory: 19456, Iterations: 0, Parallelism: 1, KeyLength: 32, SaltLength: 16},
		{Memory: 19456, Iterations: 2, Parallelism: 0, KeyLength: 32, SaltLength: 16},
		{Memory: 19456, Iterations: 2, Parallelism: 5, KeyLength: 32, SaltLength: 16},
		{Memory: 19456, Iterations: 2, Parallelism: 1, KeyLength: 15, SaltLength: 16},
		{Memory: 19456, Iterations: 2, Parallelism: 1, KeyLength: 32, SaltLength: 7},
	}
	for i, cfg := range bad {
		if err := cfg.Validate(); err == nil || !errx.Is(err, CodePasswordConfigInvalid) {
			t.Fatalf("用例 %d 应报参数非法，实际：%v", i, err)
		}
	}
}
