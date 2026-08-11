package core

import (
	"github.com/lcylpzls/testx"
	"sync"
	"testing"
	"time"
)

// TestStartCleanup 覆盖周期清理触发与停止。
func TestStartCleanup(t *testing.T) {
	var mu sync.Mutex
	count := 0
	fired := make(chan struct{}, 8)
	h := StartCleanup(10*time.Millisecond, func() int {
		mu.Lock()
		count++
		mu.Unlock()
		fired <- struct{}{}
		return 1
	})
	for i := 0; i < 2; i++ {
		select {
		case <-fired:
		case <-time.After(3 * time.Second):
			t.Fatal("清理任务未按周期触发")
		}
	}
	h.Stop()
	h.Stop() // 重复停止应安全。
	mu.Lock()
	got := count
	mu.Unlock()
	testx.RequireTrue(t, got >= 2)
}

// TestStartCleanupInvalidInterval 覆盖非法周期 panic。
func TestStartCleanupInvalidInterval(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("零周期应 panic")
		}
	}()
	StartCleanup(0, func() int { return 0 })
}

// TestStartCleanupNilFn 覆盖空清理函数 panic。
func TestStartCleanupNilFn(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("空清理函数应 panic")
		}
	}()
	StartCleanup(time.Minute, nil)
}

// TestCleanupHandleNilStop 覆盖空句柄停止安全。
func TestCleanupHandleNilStop(t *testing.T) {
	var h *CleanupHandle
	h.Stop()
}

// TestStartCleanupPanicRecover 覆盖清理函数 panic 恢复。
func TestStartCleanupPanicRecover(t *testing.T) {
	var mu sync.Mutex
	count := 0
	fired := make(chan struct{}, 4)
	h := StartCleanup(10*time.Millisecond, func() int {
		mu.Lock()
		count++
		panicking := count == 1
		mu.Unlock()
		if panicking {
			panic("清理故障")
		}
		fired <- struct{}{}
		return 1
	})
	defer h.Stop()
	select {
	case <-fired:
	case <-time.After(3 * time.Second):
		t.Fatal("panic 后后台任务应继续运行")
	}
}
