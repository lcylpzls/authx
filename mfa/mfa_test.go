package mfa

import (
	"context"
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
	if _, err := ValidateCode(secret, "287082", at, maxValidationSkew+1); err == nil ||
		!errx.Is(err, authx.CodeMFAConfigInvalid) {
		t.Fatalf("超上限 skew 应报错，实际：%v", err)
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
	if _, err := GenerateRecoveryCodes(maxRecoveryCodes + 1); err == nil ||
		!errx.Is(err, authx.CodeMFAConfigInvalid) {
		t.Fatalf("超上限数量应报错，实际：%v", err)
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

// TestTOTPConfigValidate 覆盖 TOTP 配置校验分支。
func TestTOTPConfigValidate(t *testing.T) {
	if err := DefaultTOTPConfig().Validate(); err != nil {
		t.Fatalf("默认配置应合法：%v", err)
	}
	for _, cfg := range []TOTPConfig{
		{Algorithm: Algorithm(99), Digits: 6, Period: defaultPeriod},
		{Algorithm: AlgorithmSHA1, Digits: 5, Period: defaultPeriod},
		{Algorithm: AlgorithmSHA1, Digits: 6, Period: 0},
	} {
		if err := cfg.Validate(); err == nil || !errx.Is(err, authx.CodeMFAConfigInvalid) {
			t.Fatalf("非法配置应报错，实际：%v", err)
		}
	}
}

// TestGenerateCodeSHA256 使用 RFC 6238 附录 B SHA256 向量（8 位）。
func TestGenerateCodeSHA256(t *testing.T) {
	// RFC 6238 附录 B：SHA-256 测试种子为 32 字节 "12345678901234567890123456789012"。
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA"
	cfg := TOTPConfig{Algorithm: AlgorithmSHA256, Digits: 8, Period: defaultPeriod}
	cases := []struct {
		unix int64
		want string
	}{
		{59, "46119246"},
		{1111111109, "68084774"},
		{1111111111, "67062674"},
		{1234567890, "91819424"},
		{2000000000, "90698825"},
		{20000000000, "77737706"},
	}
	for _, tc := range cases {
		got, err := GenerateCodeWithConfig(secret, time.Unix(tc.unix, 0), cfg)
		if err != nil || got != tc.want {
			t.Fatalf("SHA256 T=%d：got=%s want=%s err=%v", tc.unix, got, tc.want, err)
		}
	}
}

// TestGenerateCodeSHA512 使用 RFC 6238 附录 B SHA512 向量（8 位）。
func TestGenerateCodeSHA512(t *testing.T) {
	// RFC 6238 附录 B：SHA-512 测试种子为 64 字节 "1234567890..."（重复 6 组 + 4 位）。
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA"
	cfg := TOTPConfig{Algorithm: AlgorithmSHA512, Digits: 8, Period: defaultPeriod}
	cases := []struct {
		unix int64
		want string
	}{
		{59, "90693936"},
		{1111111109, "25091201"},
		{1111111111, "99943326"},
		{1234567890, "93441116"},
		{2000000000, "38618901"},
		{20000000000, "47863826"},
	}
	for _, tc := range cases {
		got, err := GenerateCodeWithConfig(secret, time.Unix(tc.unix, 0), cfg)
		if err != nil || got != tc.want {
			t.Fatalf("SHA512 T=%d：got=%s want=%s err=%v", tc.unix, got, tc.want, err)
		}
	}
}

// TestGenerateCodeWithConfigInvalid 覆盖生成时非法配置分支。
func TestGenerateCodeWithConfigInvalid(t *testing.T) {
	if _, err := GenerateCodeWithConfig("SECRET", time.Now(),
		TOTPConfig{Algorithm: Algorithm(9), Digits: 6, Period: defaultPeriod}); err == nil ||
		!errx.Is(err, authx.CodeMFAConfigInvalid) {
		t.Fatalf("非法配置应报错，实际：%v", err)
	}
}

// TestValidateCodeWithConfig 覆盖配置化校验分支。
func TestValidateCodeWithConfig(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA"
	cfg := TOTPConfig{Algorithm: AlgorithmSHA256, Digits: 8, Period: defaultPeriod}
	at := time.Unix(59, 0)
	ok, err := ValidateCodeWithConfig(secret, "46119246", at, 0, cfg)
	if err != nil || !ok {
		t.Fatalf("8 位正确码应通过：ok=%v err=%v", ok, err)
	}
	ok, err = ValidateCodeWithConfig(secret, "461192", at, 0, cfg)
	if err == nil || ok {
		t.Fatalf("位数不匹配应报错：ok=%v err=%v", ok, err)
	}
	ok, err = ValidateCodeWithConfig(secret, "46119246", at.Add(cfg.Period), 1, cfg)
	if err != nil || !ok {
		t.Fatalf("窗口内应通过：ok=%v err=%v", ok, err)
	}
	if _, err := ValidateCodeWithConfig(secret, "46119246", at, 0, TOTPConfig{Algorithm: Algorithm(9), Digits: 8, Period: defaultPeriod}); err == nil {
		t.Fatal("非法配置应报错")
	}
}

// TestMemoryRecoveryCodeStore 覆盖恢复码存储全部路径。
func TestMemoryRecoveryCodeStore(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	store := NewMemoryRecoveryCodeStore(func() time.Time { return now })
	if err := store.Save(ctx, "", time.Hour); err == nil || !errx.Is(err, authx.CodeMFAInvalid) {
		t.Fatalf("空哈希应报错，实际：%v", err)
	}
	if err := store.Save(ctx, "h", 0); err == nil || !errx.Is(err, authx.CodeMFAInvalid) {
		t.Fatalf("零 TTL 应报错，实际：%v", err)
	}
	if err := store.Save(ctx, "h1", time.Hour); err != nil {
		t.Fatal(err)
	}
	ok, err := store.Validate(ctx, "missing")
	if err != nil || ok {
		t.Fatalf("不存在应 false：ok=%v err=%v", ok, err)
	}
	ok, err = store.Validate(ctx, "h1")
	if err != nil || !ok {
		t.Fatalf("有效条目应 true：ok=%v err=%v", ok, err)
	}
	if _, err := store.Validate(ctx, ""); err == nil || !errx.Is(err, authx.CodeMFAInvalid) {
		t.Fatalf("空哈希校验应报错，实际：%v", err)
	}
	if err := store.Consume(ctx, "h1"); err != nil {
		t.Fatal(err)
	}
	ok, err = store.Validate(ctx, "h1")
	if err != nil || ok {
		t.Fatalf("已消费应 false：ok=%v err=%v", ok, err)
	}
	if err := store.Consume(ctx, "missing"); err == nil || !errx.Is(err, authx.CodeMFAInvalid) {
		t.Fatalf("消费不存在应报错，实际：%v", err)
	}
	if err := store.Consume(ctx, ""); err == nil || !errx.Is(err, authx.CodeMFAInvalid) {
		t.Fatalf("空哈希消费应报错，实际：%v", err)
	}
	if err := store.Save(ctx, "expired", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, "old", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, "expired-consume", time.Hour); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Hour)
	ok, err = store.Validate(ctx, "expired")
	if err != nil || ok {
		t.Fatalf("过期应 false：ok=%v err=%v", ok, err)
	}
	if err := store.Consume(ctx, "expired"); err == nil || !errx.Is(err, authx.CodeMFAInvalid) {
		t.Fatalf("消费过期应报错，实际：%v", err)
	}
	if err := store.Consume(ctx, "expired-consume"); err == nil || !errx.Is(err, authx.CodeMFAInvalid) {
		t.Fatalf("消费过期条目应报错，实际：%v", err)
	}
	if err := store.Delete(ctx, ""); err == nil || !errx.Is(err, authx.CodeMFAInvalid) {
		t.Fatalf("空哈希删除应报错，实际：%v", err)
	}
	if err := store.Delete(ctx, "h1"); err != nil {
		t.Fatal(err)
	}
	if n := store.Cleanup(); n != 1 {
		t.Fatalf("清理数量应为 1（old），实际 %d", n)
	}
}

// TestMemoryRecoveryCodeStoreLimit 覆盖容量上限与默认时钟。
func TestMemoryRecoveryCodeStoreLimit(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryRecoveryCodeStoreWithLimit(nil, 1)
	if err := store.Save(ctx, "h1", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, "h2", time.Hour); err == nil || !errx.Is(err, authx.CodeStoreFull) {
		t.Fatalf("容量已满应报错，实际：%v", err)
	}
	if err := store.Save(ctx, "h1", time.Hour); err != nil {
		t.Fatalf("更新已有不应受上限影响：%v", err)
	}
	ok, err := store.Validate(ctx, "h1")
	if err != nil || !ok {
		t.Fatalf("默认时钟读取失败：ok=%v err=%v", ok, err)
	}
	defer func() {
		if r := recover(); r == nil {
			t.Error("非正上限应 panic")
		}
	}()
	NewMemoryRecoveryCodeStoreWithLimit(nil, 0)
}

// TestMemoryRecoveryCodeStoreStartCleanup 覆盖恢复码存储周期清理。
func TestMemoryRecoveryCodeStoreStartCleanup(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	store := NewMemoryRecoveryCodeStore(func() time.Time { return now })
	if err := store.Save(ctx, "h", time.Hour); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Hour)
	h := store.StartCleanup(10 * time.Millisecond)
	defer h.Stop()
	deadline := time.Now().Add(3 * time.Second)
	for {
		ok, err := store.Validate(ctx, "h")
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("周期清理未生效")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// failingRecoveryStore 固定错误的恢复码存储桩。
type failingRecoveryStore struct {
	saveErr     error
	validateErr error
	validateOK  bool
	consumeErr  error
}

func (f failingRecoveryStore) Save(context.Context, string, time.Duration) error { return f.saveErr }
func (f failingRecoveryStore) Validate(context.Context, string) (bool, error) {
	return f.validateOK, f.validateErr
}
func (f failingRecoveryStore) Consume(context.Context, string) error { return f.consumeErr }
func (f failingRecoveryStore) Delete(context.Context, string) error  { return nil }

// TestIssueRecoveryCodes 覆盖签发与存储失败分支。
func TestIssueRecoveryCodes(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryRecoveryCodeStore(nil)
	if _, err := IssueRecoveryCodes(ctx, nil, 3, time.Hour); err == nil ||
		!errx.Is(err, authx.CodeMFAConfigInvalid) {
		t.Fatalf("空存储应报错，实际：%v", err)
	}
	codes, err := IssueRecoveryCodes(ctx, store, 3, time.Hour)
	if err != nil || len(codes) != 3 {
		t.Fatalf("签发失败：%v codes=%v", err, codes)
	}
	for _, code := range codes {
		ok, err := store.Validate(ctx, HashRecoveryCode(code))
		if err != nil || !ok {
			t.Fatalf("签发后应可校验：ok=%v err=%v", ok, err)
		}
	}
	// 生成失败。
	orig := randRead
	randRead = func(b []byte) (int, error) { return 0, errors.New("随机源故障") }
	if _, err := IssueRecoveryCodes(ctx, store, 2, time.Hour); err == nil ||
		!errx.Is(err, authx.CodeMFAInvalid) {
		t.Fatalf("随机源故障应报错，实际：%v", err)
	}
	if _, err := IssueRecoveryCodes(ctx, store, maxRecoveryCodes+1, time.Hour); err == nil ||
		!errx.Is(err, authx.CodeMFAConfigInvalid) {
		t.Fatalf("数量超限应报错，实际：%v", err)
	}
	randRead = orig
	// 存储失败。
	fail := failingRecoveryStore{saveErr: errors.New("存储故障")}
	if _, err := IssueRecoveryCodes(ctx, fail, 2, time.Hour); err == nil ||
		!errx.Is(err, authx.CodeMFAInvalid) {
		t.Fatalf("存储失败应报错，实际：%v", err)
	}
}

// TestVerifyRecoveryCodeWithStore 覆盖消费与校验分支。
func TestVerifyRecoveryCodeWithStore(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryRecoveryCodeStore(nil)
	if _, err := VerifyRecoveryCodeWithStore(ctx, nil, "code", false); err == nil ||
		!errx.Is(err, authx.CodeMFAInvalid) {
		t.Fatalf("空存储应报错，实际：%v", err)
	}
	if _, err := VerifyRecoveryCodeWithStore(ctx, store, "", false); err == nil ||
		!errx.Is(err, authx.CodeMFAInvalid) {
		t.Fatalf("空码应报错，实际：%v", err)
	}
	codes, err := IssueRecoveryCodes(ctx, store, 2, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyRecoveryCodeWithStore(ctx, store, codes[0], false)
	if err != nil || !ok {
		t.Fatalf("不消费校验应通过：ok=%v err=%v", ok, err)
	}
	ok, err = VerifyRecoveryCodeWithStore(ctx, store, codes[1], true)
	if err != nil || !ok {
		t.Fatalf("消费校验应通过：ok=%v err=%v", ok, err)
	}
	ok, err = VerifyRecoveryCodeWithStore(ctx, store, codes[1], true)
	if err != nil || ok {
		t.Fatalf("已消费不应再次通过：ok=%v err=%v", ok, err)
	}
	ok, err = VerifyRecoveryCodeWithStore(ctx, store, "WRONG", true)
	if err != nil || ok {
		t.Fatalf("错误码不应通过：ok=%v err=%v", ok, err)
	}
	fail := failingRecoveryStore{validateOK: true, consumeErr: errors.New("消费故障")}
	ok, err = VerifyRecoveryCodeWithStore(ctx, fail, "whatever", true)
	if err == nil || ok {
		t.Fatalf("消费失败应报错：ok=%v err=%v", ok, err)
	}
	failValidate := failingRecoveryStore{validateErr: errors.New("查询故障")}
	if _, err := VerifyRecoveryCodeWithStore(ctx, failValidate, "whatever", false); err == nil {
		t.Fatal("校验查询失败应透传")
	}
}
