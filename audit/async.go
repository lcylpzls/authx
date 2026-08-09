package audit

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/errx"
	"github.com/lcylpzls/logx"
)

// DropPolicy 队列满时的事件处理策略。
type DropPolicy uint8

const (
	// DropNewest 丢弃新事件并累计丢弃计数（默认，保证请求不阻塞）。
	DropNewest DropPolicy = iota
	// Block 阻塞直到队列有空间（保证不丢事件，但可能阻塞业务）。
	Block
)

// AsyncAuditor 异步审计器：事件入队后立即返回，后台批量输出与落库。
type AsyncAuditor struct {
	auditor    *Auditor
	queue      chan Event
	batchSize  int
	flushEvery time.Duration
	policy     DropPolicy
	stopCh     chan struct{}
	stopOnce   sync.Once
	done       chan struct{}
	dropped    atomic.Uint64
	running    atomic.Bool
}

// AsyncOption 异步审计器配置项。
type AsyncOption func(*AsyncAuditor) error

// WithBatchSize 设置每批最大事件数（默认 64，必须为正）。
func WithBatchSize(n int) AsyncOption {
	return func(a *AsyncAuditor) error {
		if n <= 0 {
			return errx.New(errx.KindInvalid, authx.CodeAuditQueueFull, "批大小必须为正")
		}
		a.batchSize = n
		return nil
	}
}

// WithFlushInterval 设置定时冲刷间隔（默认 100ms，必须为正）。
func WithFlushInterval(d time.Duration) AsyncOption {
	return func(a *AsyncAuditor) error {
		if d <= 0 {
			return errx.New(errx.KindInvalid, authx.CodeAuditQueueFull, "冲刷间隔必须为正")
		}
		a.flushEvery = d
		return nil
	}
}

// WithDropPolicy 设置队列满时的丢弃策略（默认 DropNewest）。
func WithDropPolicy(p DropPolicy) AsyncOption {
	return func(a *AsyncAuditor) error {
		if p != DropNewest && p != Block {
			return errx.New(errx.KindInvalid, authx.CodeAuditQueueFull, "非法丢弃策略")
		}
		a.policy = p
		return nil
	}
}

// NewAsyncAuditor 构造异步审计器；queueSize 必须为正。
func NewAsyncAuditor(logger logx.Logger, queueSize int, opts ...AsyncOption) (*AsyncAuditor, error) {
	if logger == nil {
		return nil, errx.New(errx.KindInvalid, authx.CodeAuditQueueFull, "日志器不能为空")
	}
	if queueSize <= 0 {
		return nil, errx.New(errx.KindInvalid, authx.CodeAuditQueueFull, "队列容量必须为正")
	}
	a := &AsyncAuditor{
		auditor:    New(logger),
		queue:      make(chan Event, queueSize),
		batchSize:  64,
		flushEvery: 100 * time.Millisecond,
		policy:     DropNewest,
		stopCh:     make(chan struct{}),
		done:       make(chan struct{}),
	}
	a.running.Store(true)
	for _, opt := range opts {
		if err := opt(a); err != nil {
			return nil, err
		}
	}
	go a.loop()
	return a, nil
}

// AddHook 追加持久化钩子（事件落库、告警等）。
func (a *AsyncAuditor) AddHook(fn func(Event)) {
	a.auditor.AddHook(fn)
}

// Record 异步记录审计事件；队列满时按策略处理，丢弃返回 ErrAuditQueueFull。
func (a *AsyncAuditor) Record(e Event) error {
	if !a.running.Load() {
		return errx.New(errx.KindUnavailable, authx.CodeAuditQueueFull, "审计器已停止")
	}
	switch a.policy {
	case Block:
		a.queue <- e
		return nil
	default:
		select {
		case a.queue <- e:
			return nil
		default:
			a.dropped.Add(1)
			return authx.ErrAuditQueueFull
		}
	}
}

// Dropped 返回因队列满被丢弃的事件数。
func (a *AsyncAuditor) Dropped() uint64 {
	return a.dropped.Load()
}

// Stop 停止后台处理并等待队列排空；重复调用安全。
// 注意：若注册的钩子永久阻塞，Stop 会等待其返回。
func (a *AsyncAuditor) Stop() {
	if a.running.Swap(false) {
		a.stopOnce.Do(func() { close(a.stopCh) })
	}
	<-a.done
}

// loop 后台消费队列：按批量或定时冲刷。
func (a *AsyncAuditor) loop() {
	defer close(a.done)
	buf := make([]Event, 0, a.batchSize)
	timer := time.NewTimer(a.flushEvery)
	defer timer.Stop()
	for {
		select {
		case <-a.stopCh:
			a.drain(buf)
			return
		case e := <-a.queue:
			buf = append(buf, e)
			if len(buf) >= a.batchSize {
				a.flush(buf)
				buf = buf[:0]
				timer.Reset(a.flushEvery)
			}
		case <-timer.C:
			if len(buf) > 0 {
				a.flush(buf)
				buf = buf[:0]
			}
			timer.Reset(a.flushEvery)
		}
	}
}

// drain 停止后排空剩余事件。
func (a *AsyncAuditor) drain(buf []Event) {
	if len(buf) > 0 {
		a.flush(buf)
	}
	for {
		select {
		case e := <-a.queue:
			a.auditor.Record(e)
		default:
			return
		}
	}
}

// flush 输出一批事件（日志 + 钩子）。
func (a *AsyncAuditor) flush(events []Event) {
	for _, e := range events {
		a.auditor.Record(e)
	}
}
