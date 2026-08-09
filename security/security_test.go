package security

import (
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
}

// TestRecordFailure 覆盖失败计数与锁定阈值。
func TestRecordFailure(t *testing.T) {
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	g, err := NewLoginGuard(3, 5*time.Minute, WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
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
