package authx

import (
	"testing"

	"github.com/lcylpzls/errx"
)

// TestErrVarKinds 保证预定义错误值通过 NewCode 构造后分类正确
// （注册必须先于包级变量初始化）。
func TestErrVarKinds(t *testing.T) {
	cases := map[string]struct {
		err  error
		kind errx.Kind
	}{
		"密码哈希":      {ErrPasswordHashInvalid, errx.KindInvalid},
		"密码不匹配":     {ErrPasswordMismatch, errx.KindUnauthorized},
		"密码过长":      {ErrPasswordTooLong, errx.KindInvalid},
		"密码过短":      {ErrPasswordTooShort, errx.KindInvalid},
		"令牌非法":      {ErrTokenInvalid, errx.KindUnauthorized},
		"令牌过期":      {ErrTokenExpired, errx.KindUnauthorized},
		"令牌签名":      {ErrTokenSignature, errx.KindUnauthorized},
		"令牌撤销":      {ErrTokenRevoked, errx.KindUnauthorized},
		"刷新令牌":      {ErrRefreshTokenInvalid, errx.KindUnauthorized},
		"无权限":       {ErrForbidden, errx.KindForbidden},
		"角色不存在":     {ErrRoleNotFound, errx.KindInvalid},
		"角色已存在":     {ErrRoleExists, errx.KindConflict},
		"继承环":       {ErrCycle, errx.KindInvalid},
		"RBAC 参数":   {ErrRBACInvalid, errx.KindInvalid},
		"CSRF 不匹配":  {ErrCSRFMismatch, errx.KindForbidden},
		"会话不存在":     {ErrSessionNotFound, errx.KindUnauthorized},
		"会话非法":      {ErrSessionInvalid, errx.KindInvalid},
		"会话存储":      {ErrSessionStoreInvalid, errx.KindUnavailable},
		"MFA 非法":    {ErrMFAInvalid, errx.KindInvalid},
		"MFA 配置":    {ErrMFAConfigInvalid, errx.KindInvalid},
		"OAuth2":    {ErrOAuth2Invalid, errx.KindUnauthorized},
		"OAuth2 配置": {ErrOAuth2ConfigInvalid, errx.KindInvalid},
		"安全配置":      {ErrSecurityConfigInvalid, errx.KindInvalid},
		"存储已满":      {ErrStoreFull, errx.KindUnavailable},
		"RBAC 超限":   {ErrRBACLimit, errx.KindInvalid},
		"CSRF 生成":   {ErrCSRFGenerationFailed, errx.KindUnavailable},
		"密码太弱":      {ErrPasswordTooWeak, errx.KindInvalid},
		"缺少令牌":      {ErrTokenMissing, errx.KindUnauthorized},
		"审计队列":      {ErrAuditQueueFull, errx.KindRateLimited},
	}
	for name, tc := range cases {
		if got := errx.KindOf(tc.err); got != tc.kind {
			t.Errorf("%s: Kind = %v,want %v", name, got, tc.kind)
		}
	}
}
