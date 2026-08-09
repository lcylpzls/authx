package audit

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/errx"
	"github.com/lcylpzls/logx"
)

// testAsyncLogger 构造异步审计测试日志器。
func testAsyncLogger() logx.Logger {
	logger, err := logx.NewBuilder().EnableWriter(bytes.NewBuffer(nil), logx.InfoLevel).Build()
	if err != nil {
		panic(err)
	}
	return logger
}

// TestNewAsyncAuditorErrors 覆盖构造参数校验。
func TestNewAsyncAuditorErrors(t *testing.T) {
	logger := testAsyncLogger()
	if _, err := NewAsyncAuditor(nil, 8); err == nil || !errx.Is(err, authx.CodeAuditQueueFull) {
		t.Fatalf("nil 日志器应报错，实际：%v", err)
	}
	if _, err := NewAsyncAuditor(logger, 0); err == nil || !errx.Is(err, authx.CodeAuditQueueFull) {
		t.Fatalf("零队列应报错，实际：%v", err)
	}
	if _, err := NewAsyncAuditor(logger, 8, WithBatchSize(0)); err == nil ||
		!errx.Is(err, authx.CodeAuditQueueFull) {
		t.Fatalf("零批大小应报错，实际：%v", err)
	}
	if _, err := NewAsyncAuditor(logger, 8, WithFlushInterval(0)); err == nil ||
		!errx.Is(err, authx.CodeAuditQueueFull) {
		t.Fatalf("零间隔应报错，实际：%v", err)
	}
	if _, err := NewAsyncAuditor(logger, 8, WithDropPolicy(DropPolicy(99))); err == nil ||
		!errx.Is(err, authx.CodeAuditQueueFull) {
		t.Fatalf("非法策略应报错，实际：%v", err)
	}
}

// TestAsyncAuditorDrain 覆盖停止前全部事件落库。
func TestAsyncAuditorDrain(t *testing.T) {
	a, err := NewAsyncAuditor(testAsyncLogger(), 64, WithFlushInterval(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan string, 8)
	a.AddHook(func(e Event) { got <- e.Action })
	for i := 0; i < 5; i++ {
		if err := a.Record(Event{Action: "login"}); err != nil {
			t.Fatal(err)
		}
	}
	a.Stop()
	a.Stop() // 幂等。
	for i := 0; i < 5; i++ {
		select {
		case action := <-got:
			if action != "login" {
				t.Fatalf("动作不符：%q", action)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("停止后应有 %d 条事件落库，实际 %d", 5, i)
		}
	}
}

// TestAsyncAuditorBatch 覆盖批量冲刷。
func TestAsyncAuditorBatch(t *testing.T) {
	a, err := NewAsyncAuditor(testAsyncLogger(), 16, WithBatchSize(2), WithFlushInterval(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Stop()
	got := make(chan Event, 4)
	a.AddHook(func(e Event) { got <- e })
	if err := a.Record(Event{Action: "a"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Record(Event{Action: "b"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		select {
		case e := <-got:
			if e.Action != "a" && e.Action != "b" {
				t.Fatalf("批量事件不符：%q", e.Action)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("批量未及时冲刷（第 %d 个）", i)
		}
	}
}

// TestAsyncAuditorTimer 覆盖定时冲刷。
func TestAsyncAuditorTimer(t *testing.T) {
	a, err := NewAsyncAuditor(testAsyncLogger(), 16, WithFlushInterval(20*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Stop()
	got := make(chan Event, 1)
	a.AddHook(func(e Event) { got <- e })
	if err := a.Record(Event{Action: "login"}); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-got:
		if e.Action != "login" {
			t.Fatalf("定时冲刷事件不符：%q", e.Action)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("定时冲刷未生效")
	}
}

// TestAsyncAuditorDrop 覆盖队列满丢弃策略。
func TestAsyncAuditorDrop(t *testing.T) {
	a, err := NewAsyncAuditor(testAsyncLogger(), 1, WithBatchSize(1), WithFlushInterval(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Stop()
	started := make(chan struct{})
	release := make(chan struct{})
	a.AddHook(func(Event) { close(started); <-release })
	if err := a.Record(Event{Action: "e1"}); err != nil {
		t.Fatal(err)
	}
	<-started // 后台已消费 e1 并阻塞在钩子。
	if err := a.Record(Event{Action: "e2"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Record(Event{Action: "e3"}); !errors.Is(err, authx.ErrAuditQueueFull) {
		t.Fatalf("队列满应丢弃并报错，实际：%v", err)
	}
	if got := a.Dropped(); got != 1 {
		t.Fatalf("丢弃计数应为 1，实际 %d", got)
	}
	close(release)
}

// TestAsyncAuditorBlock 覆盖阻塞策略与停止后拒绝。
func TestAsyncAuditorBlock(t *testing.T) {
	a, err := NewAsyncAuditor(testAsyncLogger(), 1, WithBatchSize(1), WithDropPolicy(Block),
		WithFlushInterval(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	a.AddHook(func(Event) { close(started); <-release })
	if err := a.Record(Event{Action: "e1"}); err != nil {
		t.Fatal(err)
	}
	<-started
	if err := a.Record(Event{Action: "e2"}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- a.Record(Event{Action: "e3"}) }()
	select {
	case <-done:
		t.Fatal("队列满时应阻塞")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("阻塞后应成功入队：%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("阻塞未解除")
	}
	a.Stop()
	if err := a.Record(Event{Action: "e3"}); err == nil ||
		!errx.Is(err, authx.CodeAuditQueueFull) {
		t.Fatalf("停止后应拒绝，实际：%v", err)
	}
}

// TestDrainDirect 白盒覆盖 drain 的两个排空分支。
func TestDrainDirect(t *testing.T) {
	got := make(chan string, 4)
	mk := func() *AsyncAuditor {
		a := &AsyncAuditor{
			auditor: New(testAsyncLogger()),
			queue:   make(chan Event, 4),
		}
		a.AddHook(func(e Event) { got <- e.Action })
		return a
	}
	// buf 非空 + 队列非空。
	a := mk()
	a.queue <- Event{Action: "queued"}
	a.drain([]Event{{Action: "buffered"}})
	// 仅队列非空。
	b := mk()
	b.queue <- Event{Action: "queued-2"}
	b.drain(nil)
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		select {
		case action := <-got:
			seen[action] = true
		case <-time.After(2 * time.Second):
			t.Fatalf("drain 未处理全部事件（第 %d 个）", i)
		}
	}
	for _, want := range []string{"buffered", "queued", "queued-2"} {
		if !seen[want] {
			t.Fatalf("drain 缺少事件：%s（已见 %v）", want, seen)
		}
	}
}
