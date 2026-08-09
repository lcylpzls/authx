package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/errx"
)

// testKey 生成测试密钥。
func testKey(t *testing.T) ([]byte, *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return []byte("0123456789abcdef0123456789abcdef"), rsaKey, ecKey, edKey
}

// TestConstructors 覆盖全部构造器与参数校验分支。
func TestConstructors(t *testing.T) {
	secret, rsaKey, ecKey, edKey := testKey(t)
	if _, err := New(nil, secret); err == nil || !errx.Is(err, authx.CodeTokenConfigInvalid) {
		t.Fatalf("空签名方法应报错，实际：%v", err)
	}
	if _, err := New(jwt.SigningMethodHS256, nil); err == nil || !errx.Is(err, authx.CodeTokenConfigInvalid) {
		t.Fatalf("空密钥应报错，实际：%v", err)
	}
	if _, err := NewHS256([]byte("short")); err == nil || !errx.Is(err, authx.CodeTokenConfigInvalid) {
		t.Fatalf("短 HMAC 密钥应报错，实际：%v", err)
	}
	if _, err := NewRS256(nil); err == nil || !errx.Is(err, authx.CodeTokenConfigInvalid) {
		t.Fatalf("空 RSA 密钥应报错，实际：%v", err)
	}
	if _, err := NewES256(nil); err == nil || !errx.Is(err, authx.CodeTokenConfigInvalid) {
		t.Fatalf("空 ECDSA 密钥应报错，实际：%v", err)
	}
	if _, err := NewEdDSA(ed25519.PrivateKey{1, 2}); err == nil || !errx.Is(err, authx.CodeTokenConfigInvalid) {
		t.Fatalf("错误长度 Ed25519 密钥应报错，实际：%v", err)
	}
	s, err := New(jwt.SigningMethodHS256, secret)
	if err != nil {
		t.Fatal(err)
	}
	if s.ttl != 15*time.Minute {
		t.Fatalf("默认有效期应为 15 分钟：%v", s.ttl)
	}
	if _, err := NewHS256(secret, WithTTL(0)); err == nil {
		t.Fatal("零 TTL 应报错")
	}
	if _, err := NewHS256(secret, WithIssuer("")); err == nil {
		t.Fatal("空签发方应报错")
	}
	if _, err := NewHS256(secret, WithAudience()); err == nil {
		t.Fatal("空受众应报错")
	}
	if _, err := NewHS256(secret, WithRevocationStore(nil)); err == nil {
		t.Fatal("空撤销列表应报错")
	}
	if _, err := NewHS256(secret, WithClock(nil)); err == nil {
		t.Fatal("空时间源应报错")
	}
	if _, err := NewRS256(rsaKey); err != nil {
		t.Fatal(err)
	}
	if _, err := NewES256(ecKey); err != nil {
		t.Fatal(err)
	}
	if _, err := NewEdDSA(edKey); err != nil {
		t.Fatal(err)
	}
}

// TestSignParseHS256 覆盖 HS256 签发/解析主流程与载荷。
func TestSignParseHS256(t *testing.T) {
	secret, _, _, _ := testKey(t)
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	s, err := NewHS256(secret, WithIssuer("myapp"), WithAudience("web", "api"),
		WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := s.Sign("u-1001", WithRoles("admin"), WithPermissions("order:read", "order:write"), WithTokenTTL(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	claims, err := s.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "u-1001" || claims.ID == "" || len(claims.Roles) != 1 ||
		len(claims.Permissions) != 2 || claims.Issuer != "myapp" {
		t.Fatalf("载荷不符：%+v", claims)
	}
	if !claims.ExpiresAt.Time.Equal(now.Add(time.Hour)) {
		t.Fatalf("TTL 覆盖失效：%v", claims.ExpiresAt)
	}
	if claims.Audience[0] != "web" {
		t.Fatalf("受众不符：%v", claims.Audience)
	}
}

// TestParseErrors 覆盖解析错误全部分支。
func TestParseErrors(t *testing.T) {
	secret, _, _, _ := testKey(t)
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	s, err := NewHS256(secret, WithIssuer("myapp"), WithAudience("web"),
		WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	good, err := s.Sign("u-1")
	if err != nil {
		t.Fatal(err)
	}
	// 篡改签名。
	tampered := good[:len(good)-4] + "AAAA"
	if _, err := s.Parse(tampered); !errx.Is(err, authx.CodeTokenSignature) {
		t.Fatalf("篡改签名应报签名错误，实际：%v", err)
	}
	// 非法令牌。
	if _, err := s.Parse("not-a-jwt"); !errx.Is(err, authx.CodeTokenSignature) {
		t.Fatalf("非法令牌应报签名/格式错误，实际：%v", err)
	}
	// 过期。
	expiredSigner, err := NewHS256(secret, WithTTL(time.Minute),
		WithClock(func() time.Time { return now.Add(-2 * time.Minute) }))
	if err != nil {
		t.Fatal(err)
	}
	expired, err := expiredSigner.Sign("u-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Parse(expired); !errx.Is(err, authx.CodeTokenExpired) {
		t.Fatalf("过期令牌应报过期，实际：%v", err)
	}
	// 签发方不匹配。
	otherIssuer, err := NewHS256(secret, WithIssuer("other"), WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	other, err := otherIssuer.Sign("u-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Parse(other); err == nil || !errx.Is(err, authx.CodeTokenInvalid) {
		t.Fatalf("签发方不匹配应报校验失败，实际：%v", err)
	}
	// 算法不匹配。
	algOther, err := NewHS256(secret, WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	algOther.method = jwt.SigningMethodHS512
	algToken, err := algOther.Sign("u-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Parse(algToken); !errx.Is(err, authx.CodeTokenSignature) {
		t.Fatalf("算法不匹配应报签名错误，实际：%v", err)
	}
	// 空主体。
	if _, err := s.Sign(""); !errx.Is(err, authx.CodeTokenInvalid) {
		t.Fatalf("空主体应报错，实际：%v", err)
	}
}

// TestParseRevoked 覆盖撤销列表命中与查询失败分支。
func TestParseRevoked(t *testing.T) {
	secret, _, _, _ := testKey(t)
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	revokedStore := NewMemoryRevocationStore(clock)
	s, err := NewHS256(secret, WithClock(clock), WithRevocationStore(revokedStore))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := s.Sign("u-1")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := s.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := revokedStore.Revoke(context.Background(), claims.ID, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Parse(raw); !errx.Is(err, authx.CodeTokenRevoked) {
		t.Fatalf("已撤销令牌应报撤销，实际：%v", err)
	}
	failStore := failingRevocationStore{err: errors.New("存储故障")}
	sf, err := NewHS256(secret, WithClock(clock), WithRevocationStore(failStore))
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := sf.Sign("u-2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sf.Parse(raw2); !errx.Is(err, authx.CodeStoreInvalid) {
		t.Fatalf("撤销查询失败应报存储错误，实际：%v", err)
	}
}

// TestNonHSAlgorithms 覆盖 RS256/ES256/EdDSA 签发与解析。
func TestNonHSAlgorithms(t *testing.T) {
	_, rsaKey, ecKey, edKey := testKey(t)
	now := func() time.Time { return time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC) }
	rsSigner, err := NewRS256(rsaKey, WithClock(now))
	if err != nil {
		t.Fatal(err)
	}
	ecSigner, err := NewES256(ecKey, WithClock(now))
	if err != nil {
		t.Fatal(err)
	}
	edSigner, err := NewEdDSA(edKey, WithClock(now))
	if err != nil {
		t.Fatal(err)
	}
	for name, signer := range map[string]*Signer{
		"rs256": rsSigner,
		"es256": ecSigner,
		"eddsa": edSigner,
	} {
		raw, err := signer.Sign("u-1")
		if err != nil {
			t.Fatalf("%s 签发失败：%v", name, err)
		}
		claims, err := signer.Parse(raw)
		if err != nil || claims.Subject != "u-1" {
			t.Fatalf("%s 解析失败：claims=%+v err=%v", name, claims, err)
		}
	}
}

// TestSignBadKeyType 覆盖签名密钥类型不匹配分支。
func TestSignBadKeyType(t *testing.T) {
	s, err := New(jwt.SigningMethodHS256, "not-a-key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign("u-1"); err == nil || !errx.Is(err, authx.CodeTokenInvalid) {
		t.Fatalf("密钥类型不匹配应报签发失败，实际：%v", err)
	}
}

// TestNewJTIError 覆盖随机源故障时签发失败（不回退弱标识）。
func TestNewJTIError(t *testing.T) {
	orig := randRead
	randRead = func(b []byte) (int, error) { return 0, errors.New("随机源故障") }
	defer func() { randRead = orig }()
	s, err := NewHS256([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign("u-1"); err == nil || !errx.Is(err, authx.CodeTokenInvalid) {
		t.Fatalf("随机源故障时签发应失败，实际：%v", err)
	}
}

// TestWithLeeway 覆盖时间容差配置与校验。
func TestWithLeeway(t *testing.T) {
	secret, _, _, _ := testKey(t)
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	if _, err := NewHS256(secret, WithLeeway(-time.Second)); err == nil ||
		!errx.Is(err, authx.CodeTokenConfigInvalid) {
		t.Fatalf("负容差应报错，实际：%v", err)
	}
	issuer, err := NewHS256(secret, WithTTL(time.Minute),
		WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := issuer.Sign("u-1")
	if err != nil {
		t.Fatal(err)
	}
	// 校验端时钟快 90 秒，容差 2 分钟 → 通过。
	lenient, err := NewHS256(secret, WithLeeway(2*time.Minute),
		WithClock(func() time.Time { return now.Add(90 * time.Second) }))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lenient.Parse(raw); err != nil {
		t.Fatalf("容差内应通过：%v", err)
	}
	// 容差仅 10 秒 → 过期。
	strict, err := NewHS256(secret, WithLeeway(10*time.Second),
		WithClock(func() time.Time { return now.Add(90 * time.Second) }))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := strict.Parse(raw); !errx.Is(err, authx.CodeTokenExpired) {
		t.Fatalf("超出容差应报过期，实际：%v", err)
	}
}

// failingRevocationStore 返回固定错误的撤销存储。
type failingRevocationStore struct {
	err error
}

func (f failingRevocationStore) Revoke(context.Context, string, time.Duration) error { return f.err }
func (f failingRevocationStore) IsRevoked(context.Context, string) (bool, error)     { return false, f.err }
