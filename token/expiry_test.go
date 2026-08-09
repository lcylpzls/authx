package token

import (
	"context"
	"testing"
	"time"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/errx"
)

// TestTokenExpiryBoundary 覆盖访问令牌到期瞬间的精确边界。
func TestTokenExpiryBoundary(t *testing.T) {
	secret, _, _, _ := testKey(t)
	base := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	now := base
	issuer, err := NewHS256(secret, WithTTL(time.Hour),
		WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := issuer.Sign("u-1")
	if err != nil {
		t.Fatal(err)
	}
	// 到期前 1ns 仍有效。
	now = base.Add(time.Hour - time.Nanosecond)
	verifier, err := NewHS256(secret, WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Parse(raw); err != nil {
		t.Fatalf("到期前 1ns 应有效：%v", err)
	}
	// 到期瞬间视为过期。
	now = base.Add(time.Hour)
	if _, err := verifier.Parse(raw); !errx.Is(err, authx.CodeTokenExpired) {
		t.Fatalf("到期瞬间应过期，实际：%v", err)
	}
}

// TestRevocationExpiryBoundary 覆盖撤销列表到期瞬间边界。
func TestRevocationExpiryBoundary(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	now := base
	store := NewMemoryRevocationStore(func() time.Time { return now })
	if err := store.Revoke(ctx, "jti-1", time.Hour); err != nil {
		t.Fatal(err)
	}
	now = base.Add(time.Hour - time.Nanosecond)
	revoked, err := store.IsRevoked(ctx, "jti-1")
	if err != nil || !revoked {
		t.Fatalf("到期前 1ns 应仍撤销：revoked=%v err=%v", revoked, err)
	}
	now = base.Add(time.Hour)
	revoked, err = store.IsRevoked(ctx, "jti-1")
	if err != nil || revoked {
		t.Fatalf("到期瞬间应解除撤销：revoked=%v err=%v", revoked, err)
	}
}

// TestRefreshExpiryBoundary 覆盖刷新令牌到期瞬间边界。
func TestRefreshExpiryBoundary(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	now := base
	store := NewMemoryRefreshStore(func() time.Time { return now })
	if err := store.Save(ctx, "h", time.Hour); err != nil {
		t.Fatal(err)
	}
	now = base.Add(time.Hour - time.Nanosecond)
	ok, err := store.Validate(ctx, "h")
	if err != nil || !ok {
		t.Fatalf("到期前 1ns 应有效：ok=%v err=%v", ok, err)
	}
	now = base.Add(time.Hour)
	ok, err = store.Validate(ctx, "h")
	if err != nil || ok {
		t.Fatalf("到期瞬间应失效：ok=%v err=%v", ok, err)
	}
}
