package mfa

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/errx"
)

// TestGenerateSecret 覆盖密钥生成。
func TestGenerateSecret(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != 32 {
		t.Fatalf("20 字节 base32 应为 32 字符：%d", len(secret))
	}
	if _, err := decodeSecret(secret); err != nil {
		t.Fatalf("生成密钥应可解码：%v", err)
	}
	orig := randRead
	randRead = func(b []byte) (int, error) { return 0, errors.New("随机源故障") }
	defer func() { randRead = orig }()
	if _, err := GenerateSecret(); err == nil || !errx.Is(err, authx.CodeMFAInvalid) {
		t.Fatalf("随机源故障应报错，实际：%v", err)
	}
}

// TestGenerateCode 使用 RFC 6238 附录 B 向量。
func TestGenerateCode(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // "12345678901234567890"
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	}
	for _, tc := range cases {
		got, err := GenerateCode(secret, time.Unix(tc.unix, 0))
		if err != nil || got != tc.want {
			t.Fatalf("T=%d：got=%s want=%s err=%v", tc.unix, got, tc.want, err)
		}
	}
	if _, err := GenerateCode("!!!", time.Now()); err == nil || !errx.Is(err, authx.CodeMFAInvalid) {
		t.Fatalf("非法密钥应报错，实际：%v", err)
	}
}

// TestValidateCode 覆盖校验窗口与格式。
func TestValidateCode(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	at := time.Unix(59, 0)
	ok, err := ValidateCode(secret, "287082", at, 0)
	if err != nil || !ok {
		t.Fatalf("正确验证码应通过：ok=%v err=%v", ok, err)
	}
	// 允许 skew=1 的相邻窗口。
	ok, err = ValidateCode(secret, "287082", at.Add(defaultPeriod), 1)
	if err != nil || !ok {
		t.Fatalf("skew 窗口应通过：ok=%v err=%v", ok, err)
	}
	ok, err = ValidateCode(secret, "287082", at.Add(3*defaultPeriod), 1)
	if err != nil || ok {
		t.Fatalf("超出窗口应失败：ok=%v err=%v", ok, err)
	}
	ok, err = ValidateCode(secret, "000000", at, 0)
	if err != nil || ok {
		t.Fatalf("错误验证码应失败：ok=%v err=%v", ok, err)
	}
	if _, err := ValidateCode(secret, "12345", at, 0); err == nil || !errx.Is(err, authx.CodeMFAInvalid) {
		t.Fatalf("长度错误应报错，实际：%v", err)
	}
	if _, err := ValidateCode(secret, "12a456", at, 0); err == nil || !errx.Is(err, authx.CodeMFAInvalid) {
		t.Fatalf("非数字应报错，实际：%v", err)
	}
	if _, err := ValidateCode("!!!", "287082", at, 0); err == nil || !errx.Is(err, authx.CodeMFAInvalid) {
		t.Fatalf("非法密钥应报错，实际：%v", err)
	}
}

// TestProvisioningURI 覆盖二维码 URI。
func TestProvisioningURI(t *testing.T) {
	uri := ProvisioningURI("SECRET", "user@example.com", "myapp")
	if !strings.HasPrefix(uri, "otpauth://totp/") ||
		!strings.Contains(uri, "secret=SECRET") ||
		!strings.Contains(uri, "issuer=myapp") {
		t.Fatalf("URI 不符：%s", uri)
	}
}

// TestRecoveryCodes 覆盖恢复码全流程。
func TestRecoveryCodes(t *testing.T) {
	if _, err := GenerateRecoveryCodes(0); err == nil || !errx.Is(err, authx.CodeMFAConfigInvalid) {
		t.Fatalf("零数量应报错，实际：%v", err)
	}
	codes, err := GenerateRecoveryCodes(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 3 {
		t.Fatalf("数量应为 3：%d", len(codes))
	}
	for _, code := range codes {
		if !strings.Contains(code, "-") {
			t.Fatalf("恢复码应按组分隔：%q", code)
		}
		hash := HashRecoveryCode(code)
		if !VerifyRecoveryCode(hash, code) {
			t.Fatal("正确恢复码应通过")
		}
		if VerifyRecoveryCode(hash, "WRONG") {
			t.Fatal("错误恢复码不应通过")
		}
	}
	orig := randRead
	randRead = func(b []byte) (int, error) { return 0, errors.New("随机源故障") }
	defer func() { randRead = orig }()
	if _, err := GenerateRecoveryCodes(2); err == nil || !errx.Is(err, authx.CodeMFAInvalid) {
		t.Fatalf("随机源故障应报错，实际：%v", err)
	}
}

// TestDecodeSecret 覆盖密钥解码兼容性。
func TestDecodeSecret(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	if _, err := decodeSecret(secret); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeSecret(strings.ToLower(secret) + "="); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeSecret(" " + secret + " "); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeSecret(""); err == nil || !errx.Is(err, authx.CodeMFAInvalid) {
		t.Fatalf("空密钥应报错，实际：%v", err)
	}
	if _, err := decodeSecret("!!!"); err == nil || !errx.Is(err, authx.CodeMFAInvalid) {
		t.Fatalf("非法密钥应报错，实际：%v", err)
	}
}

// TestHashRecoveryCode 覆盖哈希稳定性。
func TestHashRecoveryCode(t *testing.T) {
	const want = "2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b"
	if got := HashRecoveryCode("secret"); got != want {
		t.Fatalf("哈希不符：got=%s want=%s", got, want)
	}
}
