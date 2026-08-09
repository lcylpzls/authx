// Package audit 提供结构化审计日志（logx 集成）。
package audit

import (
	"fmt"
	"sync"
	"time"

	"github.com/lcylpzls/logx"
)

// 审计结果常量。
const (
	ResultSuccess  = "success"
	ResultFailure  = "failure"
	maxFieldLength = 4096 // 审计字段长度上限（防日志炸弹）
)

// Event 单条审计事件。
type Event struct {
	// Action 动作，如 login / logout / password_change / permission_change。
	Action string
	// Subject 主体（用户 ID、服务账号等）。
	Subject string
	// Object 对象（资源标识）。
	Object string
	// Result 结果：success 或 failure。
	Result string
	// Detail 补充信息（失败原因等）。
	Detail string
	// IP 来源地址。
	IP string
	// Time 事件时间；零值自动填充当前时间。
	Time time.Time
}

// Auditor 审计器：结构化日志输出 + 可插拔持久化钩子。
type Auditor struct {
	logger logx.Logger
	mu     sync.RWMutex
	hooks  []func(Event)
}

// New 构造审计器。
func New(logger logx.Logger) *Auditor {
	if logger == nil {
		panic("audit: 日志器不能为空")
	}
	return &Auditor{logger: logger}
}

// AddHook 追加持久化钩子（事件落库、告警等）。
func (a *Auditor) AddHook(fn func(Event)) {
	if fn == nil {
		panic("audit: 钩子不能为空")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.hooks = append(a.hooks, fn)
}

// Record 记录审计事件：输出结构化日志并调用全部钩子。
func (a *Auditor) Record(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	switch e.Result {
	case "", ResultSuccess:
		e.Result = ResultSuccess
	case ResultFailure:
	default:
		e.Result = ResultSuccess // 非法结果统一归为成功，避免注入任意值。
	}
	e.Action = truncate(e.Action)
	e.Subject = truncate(e.Subject)
	e.Object = truncate(e.Object)
	e.Detail = truncate(e.Detail)
	e.IP = truncate(e.IP)
	a.logger.Info("审计事件", logx.Fields(
		logx.String("audit_action", e.Action),
		logx.String("audit_subject", e.Subject),
		logx.String("audit_object", e.Object),
		logx.String("audit_result", e.Result),
		logx.String("audit_detail", e.Detail),
		logx.String("audit_ip", e.IP),
		logx.String("audit_time", e.Time.Format(time.RFC3339Nano)),
	))
	a.mu.RLock()
	hooks := append([]func(Event){}, a.hooks...)
	a.mu.RUnlock()
	for _, hook := range hooks {
		func() {
			defer func() {
				if r := recover(); r != nil {
					// 单个钩子故障不得拖垮业务主链路。
					a.logger.Error("审计钩子异常", logx.Fields(
						logx.String("audit_action", e.Action),
						logx.String("audit_panic", fmt.Sprint(r)),
					))
				}
			}()
			hook(e)
		}()
	}
}

// truncate 截断超长字段，防止审计日志被异常数据撑爆。
func truncate(s string) string {
	if len(s) > maxFieldLength {
		return s[:maxFieldLength]
	}
	return s
}
