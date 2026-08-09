package oauth2

import "context"

// userIDKey 用户 ID 上下文键类型（避免与其他库冲突）。
type userIDKey struct{}

// WithUserID 将当前登录用户 ID 写入请求上下文。
// 业务认证中间件在进入 oauth2 授权端点前调用。
func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userIDKey{}, userID)
}

// UserIDFromContext 读取当前登录用户 ID。
func UserIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(userIDKey{}).(string)
	return id, ok && id != ""
}
