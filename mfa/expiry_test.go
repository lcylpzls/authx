package mfa

import (
	"context"
	"testing"
	"time"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/errx"
)

// TestRecoveryExpiryBoundary 覆盖恢复码到期瞬间边界。
func TestRecoveryExpiryBoundary(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	now := base
	store := NewMemoryRecoveryCodeStore(func() time.Time { return now })
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
	// 消费过期瞬间。
	if err := store.Save(ctx, "h2", time.Hour); err != nil {
		t.Fatal(err)
	}
	now = base.Add(2 * time.Hour) // h2 的到期瞬间。
	if err := store.Consume(ctx, "h2"); err == nil || !errx.Is(err, authx.CodeMFAInvalid) {
		t.Fatalf("过期瞬间消费应报错，实际：%v", err)
	}
}
