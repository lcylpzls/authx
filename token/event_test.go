package token

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/testx"
)

func TestEventHook(t *testing.T) {
	hook := &fakeAuthEventHook{}
	store := NewMemoryRefreshStore(time.Now)
	ctx := context.Background()

	raw, err := IssueRefreshToken(ctx, store, time.Minute,
		WithEventHook(hook), WithTraceHook(nil))
	testx.RequireNoError(t, err)
	if _, err := ValidateRefreshToken(ctx, store, raw, WithEventHook(hook)); err != nil {
		t.Fatalf("Validate 失败：%v", err)
	}
	if _, err := RotateRefreshToken(ctx, store, raw, time.Minute, WithEventHook(hook)); err != nil {
		t.Fatalf("Rotate 失败：%v", err)
	}
	testx.RequireNoError(t, ConsumeRefreshToken(ctx, store, raw, WithEventHook(hook)))
	if _, err := ValidateRefreshToken(ctx, store, "", WithEventHook(hook)); err == nil {
		t.Fatal("空令牌应校验失败")
	}

	events := hook.snapshot()
	var actions []string
	for _, e := range events {
		actions = append(actions, e.Action)
	}
	if strings.Join(actions, ",") != "issue,validate,rotate,consume,validate" {
		t.Fatalf("事件序列不匹配：%v", actions)
	}
	if events[4].Err == nil {
		t.Fatal("失败事件应携带错误")
	}
}

func TestNoEventHook(t *testing.T) {
	store := NewMemoryRefreshStore(time.Now)
	if _, err := IssueRefreshToken(context.Background(), store, time.Minute); err != nil {
		t.Fatalf("Issue 失败：%v", err)
	}
}

type fakeAuthEventHook struct {
	mu   sync.Mutex
	list []authx.AuthEvent
}

func (h *fakeAuthEventHook) OnAuthEvent(_ context.Context, e authx.AuthEvent) {
	h.mu.Lock()
	h.list = append(h.list, e)
	h.mu.Unlock()
}

func (h *fakeAuthEventHook) snapshot() []authx.AuthEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]authx.AuthEvent(nil), h.list...)
}
