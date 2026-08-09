// Package password 提供 Argon2id 密码哈希、校验与参数迁移。
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/errx"
	"golang.org/x/crypto/argon2"
)

const (
	minPlainLength = 8    // 新密码最短长度
	maxPlainLength = 1024 // 明文长度上限（防 DoS）
)

// randRead 可替换的随机源，便于测试注入失败场景。
var randRead = rand.Read

// Hash 使用 Argon2id 派生密钥并返回标准编码的哈希串。
// 格式：$argon2id$v=19$m=<内存>,t=<时间>,p=<并行>$<盐 base64>$<密钥 base64>
func Hash(plain string, cfg authx.PasswordConfig) (string, error) {
	switch {
	case len(plain) < minPlainLength:
		return "", authx.ErrPasswordTooShort
	case len(plain) > maxPlainLength:
		return "", authx.ErrPasswordTooLong
	}
	if err := cfg.Validate(); err != nil {
		return "", err
	}
	salt := make([]byte, cfg.SaltLength)
	if _, err := randRead(salt); err != nil {
		return "", errx.Wrap(err, errx.KindUnavailable, authx.CodePasswordInternal, "随机盐生成失败")
	}
	key := argon2.IDKey([]byte(plain), salt, cfg.Iterations, cfg.Memory, cfg.Parallelism, cfg.KeyLength)
	enc := base64.RawStdEncoding
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, cfg.Memory, cfg.Iterations, cfg.Parallelism,
		enc.EncodeToString(salt), enc.EncodeToString(key),
	), nil
}

// Verify 校验明文与哈希是否匹配。
// 哈希格式非法时返回错误；明文超长返回错误；其余情况返回布尔结果。
func Verify(hash, plain string) (bool, error) {
	par, salt, key, err := parseHash(hash)
	if err != nil {
		return false, err
	}
	if len(plain) > maxPlainLength {
		return false, authx.ErrPasswordTooLong
	}
	other := argon2.IDKey([]byte(plain), salt, par.iterations, par.memory, par.parallelism, uint32(len(key)))
	return subtle.ConstantTimeCompare(key, other) == 1, nil
}

// NeedsRehash 判断哈希参数是否落后于当前配置，用于登录时惰性迁移。
func NeedsRehash(hash string, cfg authx.PasswordConfig) (bool, error) {
	par, _, _, err := parseHash(hash)
	if err != nil {
		return false, err
	}
	if err := cfg.Validate(); err != nil {
		return false, err
	}
	return par.memory != cfg.Memory || par.iterations != cfg.Iterations || par.parallelism != cfg.Parallelism, nil
}

// params 解析后的 Argon2id 参数。
type params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
}

// parseHash 解析标准编码哈希串，任何非法输入都返回统一错误。
func parseHash(hash string) (params, []byte, []byte, error) {
	var zero params
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return zero, nil, nil, wrapHashInvalid("哈希必须以 $argon2id$v=19$... 格式编码")
	}
	if parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return zero, nil, nil, wrapHashInvalid("不支持的 Argon2 版本")
	}
	par, err := parseParams(parts[3])
	if err != nil {
		return zero, nil, nil, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return zero, nil, nil, wrapHashInvalid("盐段不是合法的 base64")
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return zero, nil, nil, wrapHashInvalid("密钥段不是合法的 base64")
	}
	if len(salt) < 8 {
		return zero, nil, nil, wrapHashInvalid("盐长度至少 8 字节")
	}
	if len(key) < 16 {
		return zero, nil, nil, wrapHashInvalid("密钥长度至少 16 字节")
	}
	return par, salt, key, nil
}

// parseParams 解析 m=<内存>,t=<时间>,p=<并行> 参数段。
// 注意：此处仅要求参数结构合法（m 至少 8 KiB），以便校验历史弱参数哈希
// 完成迁移；新哈希的安全门槛由 Hash 的 cfg.Validate（至少 8MiB）保证。
func parseParams(s string) (params, error) {
	var zero params
	var memory, iterations, parallelism int
	var err error
	if _, err = fmt.Sscanf(s, "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return zero, wrapHashInvalid("参数段格式非法")
	}
	if memory < 8 {
		return zero, wrapHashInvalid("内存成本过低，至少 8KiB")
	}
	if iterations <= 0 {
		return zero, wrapHashInvalid("时间成本必须为正")
	}
	if parallelism <= 0 || parallelism > 4 {
		return zero, wrapHashInvalid("并行度必须在 1-4 之间")
	}
	return params{
		memory:      uint32(memory),
		iterations:  uint32(iterations),
		parallelism: uint8(parallelism),
	}, nil
}

// wrapHashInvalid 构造哈希格式错误（保留原错误链）。
func wrapHashInvalid(msg string) error {
	return errx.New(errx.KindInvalid, authx.CodePasswordHashInvalid, msg)
}
