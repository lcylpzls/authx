package token

import (
	"context"
	testx "github.com/lcylpzls/testx"
	"sync"
	"testing"
	"time"

	"github.com/lcylpzls/authx"
)

// traceCall 记录一次追踪调用。
type traceCall struct {
	name  string
	attrs map[string]string
	err   error
	ended bool
}

// fakeTraceHook 内存追踪钩子。
type fakeTraceHook struct {
	mu    sync.Mutex
	calls []traceCall
}

func (h *fakeTraceHook) Start(ctx context.Context, name string, attrs ...authx.TraceAttr) (context.Context, func(error)) {
	h.mu.Lock()
	h.calls = append(h.calls, traceCall{name: name, attrs: map[string]string{}})
	for _, a := range attrs {
		h.calls[len(h.calls)-1].attrs[a.Key] = a.Value
	}
	h.mu.Unlock()
	return ctx, func(err error) {
		h.mu.Lock()
		h.calls[len(h.calls)-1].err = err
		h.calls[len(h.calls)-1].ended = true
		h.mu.Unlock()
	}
}

func (h *fakeTraceHook) snapshot() []traceCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]traceCall, len(h.calls))
	copy(out, h.calls)
	return out
}

// TestTraceHook 覆盖刷新令牌四操作埋点。
func TestTraceHook(t *testing.T) {
	hook := &fakeTraceHook{}
	store := NewMemoryRefreshStore(time.Now)
	ctx := context.Background()
	raw, err := IssueRefreshToken(ctx, store, time.Minute, WithTraceHook(hook))
	testx.RequireNoError(t, err)

	if _, err := ValidateRefreshToken(ctx, store, raw, WithTraceHook(hook)); err != nil {
		t.Fatal(err)
	}
	if _, err := RotateRefreshToken(ctx, store, raw, time.Minute, WithTraceHook(hook)); err != nil {
		t.Fatal(err)
	}
	if err := ConsumeRefreshToken(ctx, store, raw, WithTraceHook(hook)); err != nil {
		t.Fatal(err)
	}
	// 失败路径。
	if _, err := ValidateRefreshToken(ctx, store, "", WithTraceHook(hook)); err == nil {
		t.Fatal("空令牌应报错")
	}

	calls := hook.snapshot()
	if len(calls) != 5 {
		t.Fatalf("应调用 5 次追踪钩子，实际：%d", len(calls))
	}
	want := []struct{ name, op string }{
		{"authx.refresh.issue", "issue"},
		{"authx.refresh.validate", "validate"},
		{"authx.refresh.rotate", "rotate"},
		{"authx.refresh.consume", "consume"},
		{"authx.refresh.validate", "validate"},
	}
	for i, w := range want {
		if calls[i].name != w.name || calls[i].attrs["authx.operation"] != w.op || !calls[i].ended {
			t.Fatalf("第 %d 次追踪调用不符：%+v", i, calls[i])
		}
	}
	if calls[4].err == nil {
		t.Fatal("失败路径应记录错误")
	}
}
