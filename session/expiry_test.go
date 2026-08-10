package session

import (
	"context"
	testx "github.com/lcylpzls/testx"
	"testing"
	"time"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/errx"
)

// TestSessionExpiryBoundary 覆盖会话到期瞬间与轮换边界。
func TestSessionExpiryBoundary(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	now := base
	store := NewMemoryStore(func() time.Time { return now })
	sess, err := store.Create(ctx, time.Hour)
	testx.RequireNoError(t, err)

	now = base.Add(time.Hour - time.Nanosecond)
	if _, err := store.Get(ctx, sess.ID); err != nil {
		t.Fatalf("到期前 1ns 应有效：%v", err)
	}
	now = base.Add(time.Hour)
	if _, err := store.Get(ctx, sess.ID); !errx.Is(err, authx.CodeSessionNotFound) {
		t.Fatalf("到期瞬间应失效，实际：%v", err)
	}
	// 轮换过期瞬间。
	sess2, err := store.Create(ctx, time.Hour)
	testx.RequireNoError(t, err)

	now = base.Add(2 * time.Hour) // sess2 的到期瞬间。
	if _, err := store.Rotate(ctx, sess2.ID, time.Hour); !errx.Is(err, authx.CodeSessionNotFound) {
		t.Fatalf("过期会话轮换应报不存在，实际：%v", err)
	}
}
