package audit

import (
	"bytes"
	testx "github.com/lcylpzls/testx"
	"strings"
	"testing"
	"time"

	"github.com/lcylpzls/logx"
)

// TestNewPanics 覆盖构造与钩子 panic 分支。
func TestNewPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("nil 日志器应 panic")
		}
	}()
	_ = New(nil)
}

// TestAddHookPanic 覆盖空钩子 panic。
func TestAddHookPanic(t *testing.T) {
	logger, err := logx.NewBuilder().EnableWriter(bytes.NewBuffer(nil), logx.InfoLevel).Build()
	testx.RequireNoError(t, err)

	a := New(logger)
	defer func() {
		if recover() == nil {
			t.Fatal("nil 钩子应 panic")
		}
	}()
	a.AddHook(nil)
}

// TestRecord 覆盖记录主流程：默认值、钩子与日志输出。
func TestRecord(t *testing.T) {
	var buf bytes.Buffer
	logger, err := logx.NewBuilder().EnableWriter(&buf, logx.InfoLevel).Build()
	testx.RequireNoError(t, err)

	a := New(logger)
	got := make(chan Event, 1)
	a.AddHook(func(e Event) { got <- e })
	a.Record(Event{Action: "login", Subject: "u-1", Object: "user:u-1", Detail: "密码错误", IP: "127.0.0.1"})
	e := <-got
	if e.Action != "login" || e.Subject != "u-1" || e.Result != ResultSuccess || e.Time.IsZero() {
		t.Fatalf("事件默认值不符：%+v", e)
	}
	if !strings.Contains(buf.String(), "audit_action") || !strings.Contains(buf.String(), "login") {
		t.Fatalf("日志输出缺少审计字段：%s", buf.String())
	}
	// 显式结果与时间保持。
	when := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	got2 := make(chan Event, 1)
	a.AddHook(func(e Event) { got2 <- e })
	a.Record(Event{Action: "logout", Result: ResultFailure, Time: when})
	e2 := <-got2
	if e2.Result != ResultFailure || !e2.Time.Equal(when) {
		t.Fatalf("显式值被覆盖：%+v", e2)
	}
}

// TestRecordTruncate 覆盖超长字段截断与非法结果归一。
func TestRecordTruncate(t *testing.T) {
	var buf bytes.Buffer
	logger, err := logx.NewBuilder().EnableWriter(&buf, logx.InfoLevel).Build()
	testx.RequireNoError(t, err)

	a := New(logger)
	got := make(chan Event, 1)
	a.AddHook(func(e Event) { got <- e })
	long := strings.Repeat("x", maxFieldLength+100)
	a.Record(Event{Action: "login", Subject: long, Result: "weird"})
	e := <-got
	if len(e.Subject) != maxFieldLength {
		t.Fatalf("超长字段应截断到上限：%d", len(e.Subject))
	}
	testx.RequireEqual(t, e.Result, ResultSuccess)

}

// TestHookPanicRecover 覆盖钩子 panic 恢复。
func TestHookPanicRecover(t *testing.T) {
	var buf bytes.Buffer
	logger, err := logx.NewBuilder().EnableWriter(&buf, logx.InfoLevel).Build()
	testx.RequireNoError(t, err)

	a := New(logger)
	a.AddHook(func(Event) { panic("钩子故障") })
	a.Record(Event{Action: "login"}) // 不应 panic。
	if !strings.Contains(buf.String(), "审计钩子异常") {
		t.Fatalf("应记录钩子异常日志：%s", buf.String())
	}
}
