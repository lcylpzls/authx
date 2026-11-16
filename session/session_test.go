package session

import (
	"context"
	"errors"
	testx "github.com/lcylpzls/testx"
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
	testx.RequireNoError(t, err)

	if sess.ID == "" || len(sess.ID) != 64 {
		t.Fatalf("会话 ID 异常：%q", sess.ID)
	}
	sess.Values["k"] = "v"
	got, err := store.Get(ctx, sess.ID)
	testx.RequireNoError(t, err)

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
	testx.RequireNoError(t, err)

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
	testx.RequireNoError(t, err)

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
	orig := randRead
	randRead = func(n int) (string, error) { return "fixed-session-id", nil }
	defer func() { randRead = orig }()
	if _, err := store.Create(ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, time.Hour); err == nil || !errx.Is(err, authx.CodeSessionStoreInvalid) {
		t.Fatalf("冲突耗尽应报存储错误，实际：%v", err)
	}
}

// TestNewSessionIDError 覆盖随机源故障返回错误（不回退弱标识）。
func TestNewSessionIDError(t *testing.T) {
	orig := randRead
	randRead = func(n int) (string, error) { return "", errors.New("随机源故障") }
	defer func() { randRead = orig }()
	if _, err := newSessionID(); err == nil {
		t.Fatal("随机源故障应返回错误")
	}
	store := NewMemoryStore(nil)
	if _, err := store.Create(context.Background(), time.Minute); err == nil ||
		!errx.Is(err, authx.CodeSessionStoreInvalid) {
		t.Fatalf("随机源故障时创建应报存储错误，实际：%v", err)
	}
}

// TestDefaultClock 覆盖默认时间源。
func TestDefaultClock(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(nil)
	sess, err := store.Create(ctx, time.Minute)
	testx.RequireNoError(t, err)

	if _, err := store.Get(ctx, sess.ID); err != nil {
		t.Fatalf("默认时间源读取失败：%v", err)
	}
}

// TestMemoryStoreWithLimit 覆盖容量上限：满时拒绝新增，允许更新已有。
func TestMemoryStoreWithLimit(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStoreWithLimit(nil, 2)
	if err := store.Save(ctx, Session{ID: "a"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, Session{ID: "b"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, Session{ID: "c"}, time.Hour); err == nil || !errx.Is(err, authx.CodeStoreFull) {
		t.Fatalf("容量已满保存应报错，实际：%v", err)
	}
	if _, err := store.Create(ctx, time.Hour); err == nil || !errx.Is(err, authx.CodeStoreFull) {
		t.Fatalf("容量已满创建应报错，实际：%v", err)
	}
	testx.RequireNoError(t, store.Save(ctx, Session{ID: "a", Values: map[string]string{"k": "v"}}, time.Hour))
}

// TestMemoryStoreLimitPanic 覆盖非法上限 panic。
func TestMemoryStoreLimitPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("非正上限应 panic")
		}
	}()
	NewMemoryStoreWithLimit(nil, 0)
}

// TestMemoryStoreStartCleanup 覆盖会话存储周期清理。
func TestMemoryStoreStartCleanup(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	store := NewMemoryStore(func() time.Time { return now })
	sess, err := store.Create(ctx, time.Hour)
	testx.RequireNoError(t, err)

	now = now.Add(2 * time.Hour)
	h := store.StartCleanup(10 * time.Millisecond)
	defer h.Stop()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := store.Get(ctx, sess.ID); err != nil {
			break // 已清理。
		}
		if time.Now().After(deadline) {
			t.Fatal("周期清理未生效")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestRotate 覆盖会话轮换全部分支。
func TestRotate(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	store := NewMemoryStore(func() time.Time { return now })
	if _, err := store.Rotate(ctx, "", time.Hour); err == nil || !errx.Is(err, authx.CodeSessionInvalid) {
		t.Fatalf("空 ID 应报错，实际：%v", err)
	}
	if _, err := store.Rotate(ctx, "x", 0); err == nil || !errx.Is(err, authx.CodeSessionInvalid) {
		t.Fatalf("零 TTL 应报错，实际：%v", err)
	}
	if _, err := store.Rotate(ctx, "missing", time.Hour); err == nil || !errx.Is(err, authx.CodeSessionNotFound) {
		t.Fatalf("不存在应报错，实际：%v", err)
	}
	old, err := store.Create(ctx, time.Hour)
	testx.RequireNoError(t, err)

	old.Values["k"] = "v"
	if err := store.Save(ctx, old, time.Hour); err != nil {
		t.Fatal(err)
	}
	rotated, err := store.Rotate(ctx, old.ID, time.Hour)
	testx.RequireNoError(t, err)

	if rotated.ID == old.ID || rotated.Values["k"] != "v" {
		t.Fatalf("轮换应保留值并更换 ID：%+v", rotated)
	}
	if _, err := store.Get(ctx, old.ID); err == nil {
		t.Fatal("旧会话应已删除")
	}
	got, err := store.Get(ctx, rotated.ID)
	if err != nil || got.Values["k"] != "v" {
		t.Fatalf("新会话应可读取：%+v err=%v", got, err)
	}
	// 过期会话轮换。
	expired, err := store.Create(ctx, time.Hour)
	testx.RequireNoError(t, err)

	now = now.Add(2 * time.Hour)
	if _, err := store.Rotate(ctx, expired.ID, time.Hour); err == nil || !errx.Is(err, authx.CodeSessionNotFound) {
		t.Fatalf("过期会话应报错，实际：%v", err)
	}
}

// TestRotateRandFail 覆盖轮换时随机源故障。
func TestRotateRandFail(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(nil)
	sess, err := store.Create(ctx, time.Hour)
	testx.RequireNoError(t, err)

	orig := randRead
	randRead = func(n int) (string, error) { return "", errors.New("随机源故障") }
	defer func() { randRead = orig }()
	if _, err := store.Rotate(ctx, sess.ID, time.Hour); err == nil ||
		!errx.Is(err, authx.CodeSessionStoreInvalid) {
		t.Fatalf("随机源故障应报错，实际：%v", err)
	}
}

// TestRotateConflict 覆盖轮换 ID 冲突耗尽。
func TestRotateConflict(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(nil)
	orig := randRead
	randRead = func(n int) (string, error) { return "fixed-session-id", nil }
	defer func() { randRead = orig }()
	sess, err := store.Create(ctx, time.Hour)
	testx.RequireNoError(t, err)

	if _, err := store.Rotate(ctx, sess.ID, time.Hour); err == nil ||
		!errx.Is(err, authx.CodeSessionStoreInvalid) {
		t.Fatalf("冲突耗尽应报错，实际：%v", err)
	}
}

// TestLifetimeSemantics 覆盖空闲续期、绝对过期和边界时间。
func TestLifetimeSemantics(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	store := NewMemoryStore(func() time.Time { return now })
	lifetime := Lifetime{IdleTTL: 30 * time.Minute, AbsoluteTTL: time.Hour}

	sess, err := store.CreateWithLifetime(ctx, lifetime)
	testx.RequireNoError(t, err)
	testx.RequireEqual(t, sess.IdleExpiresAt, now.Add(30*time.Minute))
	testx.RequireEqual(t, sess.AbsoluteExpiresAt, now.Add(time.Hour))

	now = now.Add(20 * time.Minute)
	sess.Values["k"] = "v"
	testx.RequireNoError(t, store.SaveWithLifetime(ctx, sess, lifetime))
	got, err := store.Get(ctx, sess.ID)
	testx.RequireNoError(t, err)
	testx.RequireEqual(t, got.IdleExpiresAt, now.Add(30*time.Minute))
	testx.RequireEqual(t, got.AbsoluteExpiresAt, time.Date(2026, 11, 16, 11, 0, 0, 0, time.UTC))

	now = now.Add(41 * time.Minute)
	if _, err := store.Get(ctx, sess.ID); err == nil ||
		!errx.Is(err, authx.CodeSessionNotFound) {
		t.Fatalf("持续活动也不能突破绝对期限，实际：%v", err)
	}

	idleOnly, err := store.CreateWithLifetime(ctx, Lifetime{IdleTTL: time.Minute})
	testx.RequireNoError(t, err)
	now = now.Add(time.Minute)
	if _, err := store.Get(ctx, idleOnly.ID); err == nil ||
		!errx.Is(err, authx.CodeSessionNotFound) {
		t.Fatalf("空闲期限边界应按时失效，实际：%v", err)
	}
}

// TestLifetimePersistence 覆盖保存时绝对期限不可被调用方延长。
func TestLifetimePersistence(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	store := NewMemoryStore(func() time.Time { return now })
	lifetime := Lifetime{IdleTTL: 30 * time.Minute, AbsoluteTTL: time.Hour}
	sess, err := store.CreateWithLifetime(ctx, lifetime)
	testx.RequireNoError(t, err)

	sess.AbsoluteExpiresAt = time.Time{}
	sess.IdleExpiresAt = time.Time{}
	testx.RequireNoError(t, store.SaveWithLifetime(ctx, sess, lifetime))
	got, err := store.Get(ctx, sess.ID)
	testx.RequireNoError(t, err)
	testx.RequireEqual(t, got.AbsoluteExpiresAt, time.Date(2026, 11, 16, 11, 0, 0, 0, time.UTC))

	sess.AbsoluteExpiresAt = now.Add(5 * time.Hour)
	testx.RequireNoError(t, store.SaveWithLifetime(ctx, sess, lifetime))
	got, err = store.Get(ctx, sess.ID)
	testx.RequireNoError(t, err)
	testx.RequireEqual(t, got.AbsoluteExpiresAt, time.Date(2026, 11, 16, 11, 0, 0, 0, time.UTC))

	now = now.Add(20 * time.Minute)
	rotated, err := store.RotateWithLifetime(ctx, sess.ID, lifetime)
	testx.RequireNoError(t, err)
	testx.RequireEqual(t, rotated.AbsoluteExpiresAt, got.AbsoluteExpiresAt)
	testx.RequireEqual(t, rotated.IdleExpiresAt, now.Add(30*time.Minute))

	legacy, err := store.Create(ctx, 10*time.Minute)
	testx.RequireNoError(t, err)
	migrated, err := store.RotateWithLifetime(ctx, legacy.ID, lifetime)
	testx.RequireNoError(t, err)
	testx.RequireEqual(t, migrated.AbsoluteExpiresAt, now.Add(time.Hour))
}

// TestLifetimeValidation 覆盖期限参数与新旧接口委托。
func TestLifetimeValidation(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	store := NewMemoryStore(func() time.Time { return now })
	for _, lifetime := range []Lifetime{
		{},
		{AbsoluteTTL: -time.Second},
	} {
		if _, err := store.CreateWithLifetime(ctx, lifetime); err == nil ||
			!errx.Is(err, authx.CodeSessionInvalid) {
			t.Fatalf("非法期限应报错：%+v，实际：%v", lifetime, err)
		}
	}
	if err := store.SaveWithLifetime(ctx, Session{ID: "x"}, Lifetime{}); err == nil ||
		!errx.Is(err, authx.CodeSessionInvalid) {
		t.Fatalf("保存非法期限应报错，实际：%v", err)
	}
	if _, err := store.RotateWithLifetime(ctx, "x", Lifetime{AbsoluteTTL: -1}); err == nil ||
		!errx.Is(err, authx.CodeSessionInvalid) {
		t.Fatalf("轮换非法期限应报错，实际：%v", err)
	}

	sess, err := store.Create(ctx, time.Hour)
	testx.RequireNoError(t, err)
	got, err := store.Get(ctx, sess.ID)
	testx.RequireNoError(t, err)
	testx.RequireTrue(t, got.AbsoluteExpiresAt.IsZero())

	custom := Session{ID: "custom"}
	testx.RequireNoError(t, store.SaveWithLifetime(ctx, custom,
		Lifetime{IdleTTL: time.Hour, AbsoluteTTL: time.Hour}))
	got, err = store.Get(ctx, custom.ID)
	testx.RequireNoError(t, err)
	testx.RequireEqual(t, got.AbsoluteExpiresAt, now.Add(time.Hour))
}
