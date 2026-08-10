package security

import (
	testx "github.com/lcylpzls/testx"
	"testing"
	"time"
)

// TestLockExpiryBoundary 覆盖账号锁定到期瞬间边界。
func TestLockExpiryBoundary(t *testing.T) {
	base := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	now := base
	g, err := NewLoginGuard(2, 5*time.Minute, WithClock(func() time.Time { return now }))
	testx.RequireNoError(t, err)

	_ = g.RecordFailure("u-1")
	_ = g.RecordFailure("u-1")
	if !g.IsLocked("u-1") {
		t.Fatal("应处于锁定")
	}
	now = base.Add(5*time.Minute - time.Nanosecond)
	if !g.IsLocked("u-1") {
		t.Fatal("到期前 1ns 应仍锁定")
	}
	now = base.Add(5 * time.Minute)
	if g.IsLocked("u-1") {
		t.Fatal("到期瞬间应解锁")
	}
}
