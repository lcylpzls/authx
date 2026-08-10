package authx

import "context"

// AuthEvent 描述一次认证操作事件。
type AuthEvent struct {
	// Action 操作类型：token_issue / token_validate / token_consume /
	// token_rotate。
	Action string
	// Err 操作结果错误；nil 表示成功。
	Err error
}

// EventHook 是可选事件钩子（默认 no-op），由 eventx 等外部适配器接入。
type EventHook interface {
	// OnAuthEvent 在认证操作结束时调用。
	OnAuthEvent(ctx context.Context, e AuthEvent)
}
