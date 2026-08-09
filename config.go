package authx

import "github.com/lcylpzls/errx"

// PasswordConfig Argon2id 哈希参数（RFC 9106）。
type PasswordConfig struct {
	// Memory 内存成本，单位 KiB。
	Memory uint32
	// Iterations 时间成本。
	Iterations uint32
	// Parallelism 并行度（1-4）。
	Parallelism uint8
	// KeyLength 派生密钥长度（字节，至少 16）。
	KeyLength uint32
	// SaltLength 随机盐长度（字节，至少 8）。
	SaltLength int
}

// DefaultPasswordConfig 返回 OWASP 推荐的 Argon2id 参数
// （m=19MiB、t=2、p=1），兼顾安全与自用服务端并发。
func DefaultPasswordConfig() PasswordConfig {
	return PasswordConfig{
		Memory:      19456,
		Iterations:  2,
		Parallelism: 1,
		KeyLength:   32,
		SaltLength:  16,
	}
}

// Validate 校验哈希参数是否可用于派生密钥。
func (c PasswordConfig) Validate() error {
	switch {
	case c.Memory < 8*1024:
		return errx.New(errx.KindInvalid, CodePasswordConfigInvalid, "内存成本过低，至少 8MiB")
	case c.Iterations == 0:
		return errx.New(errx.KindInvalid, CodePasswordConfigInvalid, "时间成本不能为零")
	case c.Parallelism == 0 || c.Parallelism > 4:
		return errx.New(errx.KindInvalid, CodePasswordConfigInvalid, "并行度必须在 1-4 之间")
	case c.KeyLength < 16:
		return errx.New(errx.KindInvalid, CodePasswordConfigInvalid, "密钥长度至少 16 字节")
	case c.SaltLength < 8:
		return errx.New(errx.KindInvalid, CodePasswordConfigInvalid, "盐长度至少 8 字节")
	default:
		return nil
	}
}
