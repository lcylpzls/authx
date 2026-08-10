package oauth2

import (
	"context"
	"github.com/lcylpzls/testx"
	"testing"
)

// TestUserIDContext 覆盖登录态上下文传播。
func TestUserIDContext(t *testing.T) {
	ctx := context.Background()
	_, ok := UserIDFromContext(ctx)
	testx.RequireFalse(t, ok)
	ctx = WithUserID(ctx, "u-1")
	id, ok := UserIDFromContext(ctx)
	testx.RequireTrue(t, ok)
	testx.RequireEqual(t, id, "u-1")
	ctx = WithUserID(ctx, "")
	_, ok = UserIDFromContext(ctx)
	testx.RequireFalse(t, ok)
}
