package mfa

import (
	"context"
	"testing"
	"time"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/testx"
)

// TestRecoveryExpiryBoundary 覆盖恢复码到期瞬间边界。
func TestRecoveryExpiryBoundary(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	now := base
	store := NewMemoryRecoveryCodeStore(func() time.Time { return now })
	testx.RequireNoError(t, store.Save(ctx, "h", time.Hour))
	now = base.Add(time.Hour - time.Nanosecond)
	ok, err := store.Validate(ctx, "h")
	testx.RequireNoError(t, err)
	testx.RequireTrue(t, ok)
	now = base.Add(time.Hour)
	ok, err = store.Validate(ctx, "h")
	testx.RequireNoError(t, err)
	testx.RequireFalse(t, ok)
	// 消费过期瞬间。
	testx.RequireNoError(t, store.Save(ctx, "h2", time.Hour))
	now = base.Add(2 * time.Hour) // h2 的到期瞬间。
	testx.RequireErrCode(t, store.Consume(ctx, "h2"), authx.CodeMFAInvalid)
}
