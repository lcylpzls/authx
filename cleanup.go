package authx

import (
	"sync"
	"time"
)

// CleanupHandle 周期清理任务句柄，用于停止由 StartCleanup 启动的后台循环。
type CleanupHandle struct {
	once sync.Once
	stop chan struct{}
	done chan struct{}
}

// StartCleanup 启动周期清理后台任务：按 interval 周期调用 fn，返回句柄。
// interval 必须为正，否则 panic（配置错误应尽早暴露）。
// 调用方无需持有返回句柄；进程退出时 goroutine 自动结束。
func StartCleanup(interval time.Duration, fn func() int) *CleanupHandle {
	if interval <= 0 {
		panic("authx: 清理周期必须为正")
	}
	if fn == nil {
		panic("authx: 清理函数不能为空")
	}
	h := &CleanupHandle{
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	go func() {
		defer close(h.done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				fn()
			case <-h.stop:
				return
			}
		}
	}()
	return h
}

// Stop 停止清理任务并等待后台 goroutine 退出；重复调用安全。
func (h *CleanupHandle) Stop() {
	if h == nil {
		return
	}
	h.once.Do(func() { close(h.stop) })
	<-h.done
}
