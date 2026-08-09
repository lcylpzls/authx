package password

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/errx"
)

// TestHashAndVerify 覆盖哈希与校验主流程。
func TestHashAndVerify(t *testing.T) {
	h, err := Hash("password123", authx.DefaultPasswordConfig())
	if err != nil {
		t.Fatalf("Hash 失败：%v", err)
	}
	ok, err := Verify(h, "password123")
	if err != nil || !ok {
		t.Fatalf("正确明文应校验通过：ok=%v err=%v", ok, err)
	}
	ok, err = Verify(h, "wrong-password")
	if err != nil || ok {
		t.Fatalf("错误明文应校验失败：ok=%v err=%v", ok, err)
	}
}

// TestHashSaltRandom 覆盖盐随机性：相同明文两次哈希结果不同。
func TestHashSaltRandom(t *testing.T) {
	a, err := Hash("password123", authx.DefaultPasswordConfig())
	if err != nil {
		t.Fatal(err)
	}
	b, err := Hash("password123", authx.DefaultPasswordConfig())
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("两次哈希结果不应相同（盐必须随机）")
	}
}

// TestHashLengthBounds 覆盖明文长度上下限。
func TestHashLengthBounds(t *testing.T) {
	cfg := authx.DefaultPasswordConfig()
	if _, err := Hash("1234567", cfg); !errors.Is(err, authx.ErrPasswordTooShort) {
		t.Fatalf("7 字节明文应报过短，实际：%v", err)
	}
	long := strings.Repeat("a", 1025)
	if _, err := Hash(long, cfg); !errors.Is(err, authx.ErrPasswordTooLong) {
		t.Fatalf("1025 字节明文应报过长，实际：%v", err)
	}
}

// TestHashInvalidConfig 覆盖参数校验全部分支。
func TestHashInvalidConfig(t *testing.T) {
	bad := []authx.PasswordConfig{
		{Memory: 8191, Iterations: 2, Parallelism: 1, KeyLength: 32, SaltLength: 16},
		{Memory: 19456, Iterations: 0, Parallelism: 1, KeyLength: 32, SaltLength: 16},
		{Memory: 19456, Iterations: 2, Parallelism: 0, KeyLength: 32, SaltLength: 16},
		{Memory: 19456, Iterations: 2, Parallelism: 5, KeyLength: 32, SaltLength: 16},
		{Memory: 19456, Iterations: 2, Parallelism: 1, KeyLength: 15, SaltLength: 16},
		{Memory: 19456, Iterations: 2, Parallelism: 1, KeyLength: 32, SaltLength: 7},
	}
	for i, cfg := range bad {
		_, err := Hash("password123", cfg)
		if err == nil || !errx.Is(err, authx.CodePasswordConfigInvalid) {
			t.Fatalf("用例 %d 应报参数非法，实际：%v", i, err)
		}
	}
	if err := authx.DefaultPasswordConfig().Validate(); err != nil {
		t.Fatalf("默认配置应合法：%v", err)
	}
}

// TestHashRandFailure 覆盖随机盐生成失败分支。
func TestHashRandFailure(t *testing.T) {
	orig := randRead
	randRead = func(b []byte) (int, error) { return 0, errors.New("随机源故障") }
	defer func() { randRead = orig }()
	_, err := Hash("password123", authx.DefaultPasswordConfig())
	if err == nil || !errx.Is(err, authx.CodePasswordInternal) {
		t.Fatalf("随机源故障应返回内部错误，实际：%v", err)
	}
}

// TestVerifyKnownVector 使用 x/crypto 官方向量验证全链路（哈希解析 + 派生）。
// 向量：Argon2id，password="password"，salt="somesalt"，t=2、m=64、p=1。
func TestVerifyKnownVector(t *testing.T) {
	salt := []byte("somesalt")
	key, err := hex.DecodeString("068d62b26455936aa6ebe60060b0a65870dbfa3ddf8d41f7")
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawStdEncoding
	h := fmt.Sprintf("$argon2id$v=19$m=64,t=2,p=1$%s$%s",
		enc.EncodeToString(salt), enc.EncodeToString(key))
	ok, err := Verify(h, "password")
	if err != nil || !ok {
		t.Fatalf("官方向量应校验通过：ok=%v err=%v", ok, err)
	}
	ok, err = Verify(h, "wrong")
	if err != nil || ok {
		t.Fatalf("错误明文应校验失败：ok=%v err=%v", ok, err)
	}
}

// TestVerifyHashFormatErrors 覆盖解析错误的全部路径。
func TestVerifyHashFormatErrors(t *testing.T) {
	enc := base64.RawStdEncoding
	salt := enc.EncodeToString(bytes.Repeat([]byte{0x02}, 16))
	key := enc.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	bad := []string{
		"",
		"foo",
		"$md5$v=19$m=32,t=3,p=4$" + salt + "$" + key,
		"$argon2id$v=18$m=32,t=3,p=4$" + salt + "$" + key,
		"$argon2id$v=19$m=32,t=3$" + salt + "$" + key,
		"$argon2id$v=19$m=1,t=3,p=4$" + salt + "$" + key,
		"$argon2id$v=19$m=262145,t=3,p=4$" + salt + "$" + key,
		"$argon2id$v=19$m=32,t=1001,p=4$" + salt + "$" + key,
		"$argon2id$v=19$m=32,t=0,p=4$" + salt + "$" + key,
		"$argon2id$v=19$m=32,t=3,p=0$" + salt + "$" + key,
		"$argon2id$v=19$m=32,t=3,p=5$" + salt + "$" + key,
		"$argon2id$v=19$m=32,t=3,p=4$%%%$" + key,
		"$argon2id$v=19$m=32,t=3,p=4$" + salt + "$%%%",
		"$argon2id$v=19$m=32,t=3,p=4$" + enc.EncodeToString([]byte{0x01, 0x02}) + "$" + key,
		"$argon2id$v=19$m=32,t=3,p=4$" + salt + "$" + enc.EncodeToString([]byte{0x11}),
		"$argon2id$v=19$m=32,t=3,p=4$" + enc.EncodeToString(make([]byte, 1025)) + "$" + key,
		"$argon2id$v=19$m=32,t=3,p=4$" + salt + "$" + enc.EncodeToString(make([]byte, 4097)),
	}
	for i, h := range bad {
		if _, err := Verify(h, "password123"); err == nil || !errx.Is(err, authx.CodePasswordHashInvalid) {
			t.Fatalf("用例 %d（%q）应报哈希格式错误，实际：%v", i, h, err)
		}
	}
}

// TestVerifyTooLongPlain 覆盖校验阶段明文超长分支。
func TestVerifyTooLongPlain(t *testing.T) {
	h, err := Hash("password123", authx.DefaultPasswordConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(h, strings.Repeat("a", 1025)); !errors.Is(err, authx.ErrPasswordTooLong) {
		t.Fatalf("超长明文应报过长，实际：%v", err)
	}
}

// TestNeedsRehash 覆盖参数迁移检测。
func TestNeedsRehash(t *testing.T) {
	cfg := authx.DefaultPasswordConfig()
	h, err := Hash("password123", cfg)
	if err != nil {
		t.Fatal(err)
	}
	need, err := NeedsRehash(h, cfg)
	if err != nil || need {
		t.Fatalf("相同参数不应需要迁移：need=%v err=%v", need, err)
	}
	other := cfg
	other.Memory = 32768
	need, err = NeedsRehash(h, other)
	if err != nil || !need {
		t.Fatalf("内存参数不同应需要迁移：need=%v err=%v", need, err)
	}
	other = cfg
	other.Iterations = 3
	need, err = NeedsRehash(h, other)
	if err != nil || !need {
		t.Fatalf("时间参数不同应需要迁移：need=%v err=%v", need, err)
	}
	other = cfg
	other.Parallelism = 2
	need, err = NeedsRehash(h, other)
	if err != nil || !need {
		t.Fatalf("并行参数不同应需要迁移：need=%v err=%v", need, err)
	}
	if _, err := NeedsRehash("bad-hash", cfg); err == nil || !errx.Is(err, authx.CodePasswordHashInvalid) {
		t.Fatalf("非法哈希应报错，实际：%v", err)
	}
	badCfg := cfg
	badCfg.Memory = 0
	if _, err := NeedsRehash(h, badCfg); err == nil || !errx.Is(err, authx.CodePasswordConfigInvalid) {
		t.Fatalf("非法配置应报错，实际：%v", err)
	}
}
