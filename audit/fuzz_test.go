package audit

import (
	"bytes"
	"testing"

	"github.com/lcylpzls/logx"
)

// FuzzAuditEvent 模糊测试审计事件处理，确保任意输入不 panic。
func FuzzAuditEvent(f *testing.F) {
	logger, err := logx.NewBuilder().EnableWriter(bytes.NewBuffer(nil), logx.InfoLevel).Build()
	if err != nil {
		f.Fatal(err)
	}
	f.Add("login", "u-1", "order:1", "detail", "127.0.0.1", "success")
	f.Add("x", "", "", "", "", "weird")
	a := New(logger)
	a.AddHook(func(Event) {})
	a.AddHook(func(Event) { panic("钩子故障") })
	f.Fuzz(func(t *testing.T, action, subject, object, detail, ip, result string) {
		a.Record(Event{Action: action, Subject: subject, Object: object,
			Detail: detail, IP: ip, Result: result})
	})
}
