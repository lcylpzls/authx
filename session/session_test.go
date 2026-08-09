package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/errx"
)

// TestMemoryStore 覆盖会话存储全部路径。
func TestMemoryStore(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	store := NewMemoryStore(func() time.Time { return now })
	if _, err := store.Create(ctx, 0); err == nil || !errx.Is(err, authx.CodeSessionInvalid) {
		t.Fatalf("零 TTL 应报错，实际：%v", err)
	}
	sess, err := store.Create(ctx, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if sess.ID == "" || len(sess.ID) != 64 {
		t.Fatalf("会话 ID 异常：%q", sess.ID)
	}
	sess.Values["k"] = "v"
	got, err := store.Get(ctx, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Values["k"] != "" {
		t.Fatal("Get 应返回存储副本，外部修改不应影响")
	}
	// 覆盖 cloneSession 非空 Values 循环。
	if err := store.Save(ctx, Session{ID: "with-values", Values: map[string]string{"a": "b"}}, time.Hour); err != nil {
		t.Fatal(err)
	}
	full, err := store.Get(ctx, "with-values")
	if err != nil || full.Values["a"] != "b" {
		t.Fatalf("带值会话读取失败：%+v err=%v", full, err)
	}
	if _, err := store.Get(ctx, "missing"); err == nil || !errx.Is(err, authx.CodeSessionNotFound) {
		t.Fatalf("不存在会话应报错，实际：%v", err)
	}
	if _, err := store.Get(ctx, ""); err == nil || !errx.Is(err, authx.CodeSessionInvalid) {
		t.Fatalf("空 ID 应报错，实际：%v", err)
	}
	expired, err := store.Create(ctx, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Hour)
	if _, err := store.Get(ctx, expired.ID); err == nil || !errx.Is(err, authx.CodeSessionNotFound) {
		t.Fatalf("过期会话应报错，实际：%v", err)
	}
	if err := store.Save(ctx, Session{}, time.Hour); err == nil || !errx.Is(err, authx.CodeSessionInvalid) {
		t.Fatalf("空 ID 保存应报错，实际：%v", err)
	}
	if err := store.Save(ctx, Session{ID: "x"}, 0); err == nil || !errx.Is(err, authx.CodeSessionInvalid) {
		t.Fatalf("零 TTL 保存应报错，实际：%v", err)
	}
	if err := store.Delete(ctx, ""); err == nil || !errx.Is(err, authx.CodeSessionInvalid) {
		t.Fatalf("空 ID 删除应报错，实际：%v", err)
	}
	if err := store.Delete(ctx, sess.ID); err != nil {
		t.Fatal(err)
	}
	old, err := store.Create(ctx, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_ = old
	now = now.Add(2 * time.Hour)
	if n := store.Cleanup(); n != 2 {
		t.Fatalf("清理数量应为 2（with-values 与 old；expired 已由 Get 清理，sess 已由 Delete 删除），实际 %d", n)
	}
}

// TestCreateConflict 覆盖会话 ID 冲突重试与耗尽。
func TestCreateConflict(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(nil)
	fixed := []byte("0123456789abcdef0123456789abcdef")
	orig := randRead
	randRead = func(b []byte) (int, error) { return copy(b, fixed), nil }
	defer func() { randRead = orig }()
	if _, err := store.Create(ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, time.Hour); err == nil || !errx.Is(err, authx.CodeSessionStoreInvalid) {
		t.Fatalf("冲突耗尽应报存储错误，实际：%v", err)
	}
}

// TestNewSessionIDFallback 覆盖随机源故障回退。
func TestNewSessionIDFallback(t *testing.T) {
	orig := randRead
	randRead = func(b []byte) (int, error) { return 0, errors.New("随机源故障") }
	defer func() { randRead = orig }()
	id := newSessionID()
	if len(id) == 0 {
		t.Fatal("回退 ID 不应为空")
	}
}

// TestDefaultClock 覆盖默认时间源。
func TestDefaultClock(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(nil)
	sess, err := store.Create(ctx, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, sess.ID); err != nil {
		t.Fatalf("默认时间源读取失败：%v", err)
	}
}
