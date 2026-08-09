package oauth2

import (
	"context"
	"testing"
)

// TestUserIDContext 覆盖登录态上下文传播。
func TestUserIDContext(t *testing.T) {
	ctx := context.Background()
	if _, ok := UserIDFromContext(ctx); ok {
		t.Fatal("空上下文不应有用户")
	}
	ctx = WithUserID(ctx, "u-1")
	id, ok := UserIDFromContext(ctx)
	if !ok || id != "u-1" {
		t.Fatalf("用户 ID 不符：%q %v", id, ok)
	}
	ctx = WithUserID(ctx, "")
	if _, ok := UserIDFromContext(ctx); ok {
		t.Fatal("空用户 ID 不应通过")
	}
}
