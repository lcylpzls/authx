package security

import (
	"context"
	"errors"
	testx "github.com/lcylpzls/testx"
	"testing"
	"time"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/errx"
)

// TestNewErrors 覆盖构造参数校验。
func TestNewErrors(t *testing.T) {
	if _, err := NewLoginGuard(0, time.Minute); err == nil || !errx.Is(err, authx.CodeSecurityConfigInvalid) {
		t.Fatalf("零失败次数应报错，实际：%v", err)
	}
	if _, err := NewLoginGuard(3, 0); err == nil || !errx.Is(err, authx.CodeSecurityConfigInvalid) {
		t.Fatalf("零锁定时长应报错，实际：%v", err)
	}
	if _, err := NewLoginGuard(3, time.Minute, WithFailureWindow(0)); err == nil ||
		!errx.Is(err, authx.CodeSecurityConfigInvalid) {
		t.Fatalf("零窗口应报错，实际：%v", err)
	}
	if _, err := NewLoginGuard(3, time.Minute, WithClock(nil)); err == nil ||
		!errx.Is(err, authx.CodeSecurityConfigInvalid) {
		t.Fatalf("空时间源应报错，实际：%v", err)
	}
	if _, err := NewLoginGuard(3, time.Minute, WithGuardStore(nil)); err == nil ||
		!errx.Is(err, authx.CodeSecurityConfigInvalid) {
		t.Fatalf("空存储应报错，实际：%v", err)
	}
}

// TestRecordFailure 覆盖失败计数与锁定阈值。
func TestRecordFailure(t *testing.T) {
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	g, err := NewLoginGuard(3, 5*time.Minute, WithClock(func() time.Time { return now }))
	testx.RequireNoError(t, err)

	if g.RecordFailure("u-1") {
		t.Fatal("首次失败不应锁定")
	}
	if g.RecordFailure("u-1") {
		t.Fatal("二次失败不应锁定")
	}
	if !g.RecordFailure("u-1") {
		t.Fatal("三次失败应锁定")
	}
	if !g.IsLocked("u-1") {
		t.Fatal("锁定状态应为 true")
	}
	if !g.RecordFailure("u-1") {
		t.Fatal("锁定中失败应返回 true")
	}
}

// TestIsLockedExpire 覆盖锁定过期自动解锁。
func TestIsLockedExpire(t *testing.T) {
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	g, err := NewLoginGuard(2, time.Minute, WithClock(func() time.Time { return now }))
	testx.RequireNoError(t, err)

	_ = g.RecordFailure("u-1")
	_ = g.RecordFailure("u-1")
	if !g.IsLocked("u-1") {
		t.Fatal("应处于锁定")
	}
	now = now.Add(2 * time.Minute)
	if g.IsLocked("u-1") {
		t.Fatal("过期后应自动解锁")
	}
}

// TestReset 覆盖成功登录后的复位。
func TestReset(t *testing.T) {
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	g, err := NewLoginGuard(2, time.Minute, WithClock(func() time.Time { return now }))
	testx.RequireNoError(t, err)

	_ = g.RecordFailure("u-1")
	g.Reset("u-1")
	if g.IsLocked("u-1") {
		t.Fatal("复位后不应锁定")
	}
	if g.RecordFailure("u-1") {
		t.Fatal("复位后应从零计数")
	}
}

// TestWindowSliding 覆盖滑动窗口内旧失败过期。
func TestWindowSliding(t *testing.T) {
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	g, err := NewLoginGuard(3, time.Minute, WithFailureWindow(5*time.Minute),
		WithClock(func() time.Time { return now }))
	testx.RequireNoError(t, err)

	_ = g.RecordFailure("u-1")
	_ = g.RecordFailure("u-1")
	now = now.Add(6 * time.Minute)
	if g.RecordFailure("u-1") {
		t.Fatal("窗口外失败过期后不应触发锁定")
	}
	// 再次积累达到阈值。
	_ = g.RecordFailure("u-1")
	if !g.RecordFailure("u-1") {
		t.Fatal("窗口内积累应触发锁定")
	}
}

// TestCleanup 覆盖过期记录清理。
func TestCleanup(t *testing.T) {
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	g, err := NewLoginGuard(2, time.Minute, WithFailureWindow(5*time.Minute),
		WithClock(func() time.Time { return now }))
	testx.RequireNoError(t, err)

	_ = g.RecordFailure("u-locked")
	_ = g.RecordFailure("u-locked")
	_ = g.RecordFailure("u-failures")
	now = now.Add(10 * time.Minute)
	if n := g.Cleanup(); n != 2 {
		t.Fatalf("清理数量应为 2（锁定与失败记录各一），实际 %d", n)
	}
	if g.IsLocked("u-locked") {
		t.Fatal("清理后不应锁定")
	}
}

// TestCleanupPartial 覆盖失败记录部分过期保留分支。
func TestCleanupPartial(t *testing.T) {
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	g, err := NewLoginGuard(10, time.Minute, WithFailureWindow(5*time.Minute),
		WithClock(func() time.Time { return now }))
	testx.RequireNoError(t, err)

	_ = g.RecordFailure("u-mixed")
	_ = g.RecordFailure("u-mixed")
	now = now.Add(6 * time.Minute)
	_ = g.RecordFailure("u-mixed")
	if n := g.Cleanup(); n != 0 {
		t.Fatalf("部分过期记录应保留且不计数，实际 %d", n)
	}
	// 保留的记录仍在窗口内，可继续累计。
	_ = g.RecordFailure("u-mixed")
	if g.RecordFailure("u-mixed") {
		t.Fatal("保留计数不应错误触发锁定")
	}
}

// TestWithMaxEntriesInvalid 覆盖非法条目上限。
func TestWithMaxEntriesInvalid(t *testing.T) {
	if _, err := NewLoginGuard(3, time.Minute, WithMaxEntries(0)); err == nil ||
		!errx.Is(err, authx.CodeSecurityConfigInvalid) {
		t.Fatalf("非正上限应报错，实际：%v", err)
	}
}

// TestMaxEntriesFull 覆盖容量满时拒绝记录新主体。
func TestMaxEntriesFull(t *testing.T) {
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	g, err := NewLoginGuard(3, time.Minute, WithMaxEntries(2),
		WithClock(func() time.Time { return now }))
	testx.RequireNoError(t, err)

	_ = g.RecordFailure("a")
	_ = g.RecordFailure("b")
	if g.RecordFailure("c") {
		t.Fatal("容量满时新主体不应触发锁定")
	}
	if g.IsLocked("c") {
		t.Fatal("容量满时新主体不应被记录")
	}
	// 已记录主体在容量满时仍可继续累计。
	if g.RecordFailure("a") {
		t.Fatal("已记录主体应继续累计")
	}
}

// TestLoginGuardStartCleanup 覆盖守卫周期清理。
func TestLoginGuardStartCleanup(t *testing.T) {
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	g, err := NewLoginGuard(2, time.Minute, WithClock(func() time.Time { return now }))
	testx.RequireNoError(t, err)

	_ = g.RecordFailure("u-1")
	_ = g.RecordFailure("u-1")
	if !g.IsLocked("u-1") {
		t.Fatal("应处于锁定")
	}
	now = now.Add(2 * time.Minute)
	h := g.StartCleanup(10 * time.Millisecond)
	defer h.Stop()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if !g.IsLocked("u-1") {
			break // 已清理解锁。
		}
		if time.Now().After(deadline) {
			t.Fatal("周期清理未生效")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestSharedGuardStore 覆盖多实例共享状态、成功复位和自动解锁。
func TestSharedGuardStore(t *testing.T) {
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	store := NewMemoryGuardStore(defaultMaxEntries)
	newGuard := func() *LoginGuard {
		g, err := NewLoginGuard(2, time.Minute,
			WithClock(func() time.Time { return now }),
			WithGuardStore(store))
		testx.RequireNoError(t, err)
		return g
	}
	first, second := newGuard(), newGuard()

	_ = first.RecordFailure("u-1")
	_ = first.RecordFailure("u-1")
	if !second.IsLocked("u-1") {
		t.Fatal("共享存储应跨实例看到锁定状态")
	}
	second.Reset("u-1")
	if first.IsLocked("u-1") {
		t.Fatal("共享复位后应立即解锁")
	}

	_ = second.RecordFailure("u-2")
	_ = second.RecordFailure("u-2")
	now = now.Add(2 * time.Minute)
	if first.IsLocked("u-2") {
		t.Fatal("锁定期到达后应自动解锁")
	}
}

// TestGuardStoreErrors 覆盖自定义存储故障时默认 fail-closed 与错误透传。
func TestGuardStoreErrors(t *testing.T) {
	sentinel := errors.New("存储故障")
	store := &failingGuardStore{err: sentinel}
	g, err := NewLoginGuard(2, time.Minute, WithGuardStore(store))
	testx.RequireNoError(t, err)

	if !g.RecordFailure("u-1") {
		t.Fatal("记录失败发生存储故障时应按锁定处理")
	}
	if !g.IsLocked("u-1") {
		t.Fatal("查询发生存储故障时应按锁定处理")
	}
	if locked, err := g.RecordFailureContext(context.Background(), "u-1"); locked ||
		!errors.Is(err, sentinel) {
		t.Fatalf("应透传存储错误：locked=%v err=%v", locked, err)
	}
	if locked, err := g.IsLockedContext(context.Background(), "u-1"); locked ||
		!errors.Is(err, sentinel) {
		t.Fatalf("应透传查询错误：locked=%v err=%v", locked, err)
	}
	if err := g.ResetContext(context.Background(), "u-1"); !errors.Is(err, sentinel) {
		t.Fatalf("应透传复位错误：%v", err)
	}
	g.Reset("u-1")
	if _, err := g.CleanupContext(context.Background()); !errors.Is(err, sentinel) {
		t.Fatalf("应透传清理错误：%v", err)
	}
	if n := g.Cleanup(); n != 0 {
		t.Fatalf("清理故障应返回零，实际：%d", n)
	}
}

// TestMemoryGuardStoreValidation 覆盖存储独立调用时拒绝非法策略。
func TestMemoryGuardStoreValidation(t *testing.T) {
	store := NewMemoryGuardStore(1)
	now := time.Now()
	if _, err := store.RecordFailure(context.Background(), "u", now, GuardPolicy{}); err == nil ||
		!errx.Is(err, authx.CodeSecurityConfigInvalid) {
		t.Fatalf("非法记录策略应报错，实际：%v", err)
	}
	if _, err := store.Cleanup(context.Background(), now, GuardPolicy{}); err == nil ||
		!errx.Is(err, authx.CodeSecurityConfigInvalid) {
		t.Fatalf("非法清理策略应报错，实际：%v", err)
	}
}

// TestNewMemoryGuardStorePanic 覆盖非法容量。
func TestNewMemoryGuardStorePanic(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("非正容量应 panic")
		}
	}()
	NewMemoryGuardStore(0)
}

// TestStartCleanupCallsStore 覆盖周期任务对 GuardStore.Cleanup 的调用。
func TestStartCleanupCallsStore(t *testing.T) {
	store := &cleanupSignalStore{called: make(chan struct{}, 1)}
	g, err := NewLoginGuard(2, time.Minute, WithGuardStore(store))
	testx.RequireNoError(t, err)
	handle := g.StartCleanup(10 * time.Millisecond)
	defer handle.Stop()
	select {
	case <-store.called:
	case <-time.After(3 * time.Second):
		t.Fatal("周期清理未调用存储")
	}
}

type failingGuardStore struct {
	err error
}

type cleanupSignalStore struct {
	called chan struct{}
}

func (s *cleanupSignalStore) RecordFailure(
	context.Context,
	string,
	time.Time,
	GuardPolicy,
) (bool, error) {
	return false, nil
}

func (s *cleanupSignalStore) IsLocked(context.Context, string, time.Time) (bool, error) {
	return false, nil
}

func (s *cleanupSignalStore) Reset(context.Context, string) error {
	return nil
}

func (s *cleanupSignalStore) Cleanup(context.Context, time.Time, GuardPolicy) (int, error) {
	select {
	case s.called <- struct{}{}:
	default:
	}
	return 0, nil
}

func (s *failingGuardStore) RecordFailure(
	context.Context,
	string,
	time.Time,
	GuardPolicy,
) (bool, error) {
	return false, s.err
}

func (s *failingGuardStore) IsLocked(context.Context, string, time.Time) (bool, error) {
	return false, s.err
}

func (s *failingGuardStore) Reset(context.Context, string) error {
	return s.err
}

func (s *failingGuardStore) Cleanup(context.Context, time.Time, GuardPolicy) (int, error) {
	return 0, s.err
}
