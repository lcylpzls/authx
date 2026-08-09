// Package middleware 提供 webx 认证、授权与 CSRF 中间件。
package middleware

import (
	"net/http"
	"strings"

	"github.com/lcylpzls/authx/rbac"
	"github.com/lcylpzls/authx/token"
	"github.com/lcylpzls/webx"
)

const (
	ctxKeyClaims = "authx_claims"
	ctxKeyUserID = "authx_user_id"
)

// authOptions 认证中间件配置。
type authOptions struct {
	realm string
}

// Option 认证中间件配置项。
type Option func(*authOptions)

// WithRealm 设置 WWW-Authenticate 提示域。
func WithRealm(realm string) Option {
	return func(o *authOptions) { o.realm = realm }
}

// Auth 构造 Bearer Token 认证中间件：解析并校验令牌，注入用户身份。
// 校验失败返回 401 标准响应；成功后调用 c.Next() 继续处理链。
func Auth(signer *token.Signer, opts ...Option) webx.HandlerFunc {
	if signer == nil {
		panic("authx: 签发器不能为空")
	}
	o := &authOptions{realm: "api"}
	for _, opt := range opts {
		opt(o)
	}
	return func(c *webx.Context) {
		raw, ok := bearerToken(c.GetHeader("Authorization"))
		if !ok {
			c.Header("WWW-Authenticate", "Bearer realm="+o.realm)
			c.AbortWithStatusJSON(http.StatusUnauthorized, "未认证", nil)
			return
		}
		claims, err := signer.Parse(raw)
		if err != nil {
			c.Header("WWW-Authenticate", "Bearer realm="+o.realm)
			c.AbortWithStatusJSON(http.StatusUnauthorized, "未认证或令牌无效", nil)
			return
		}
		c.Set(ctxKeyClaims, claims)
		c.Set(ctxKeyUserID, claims.Subject)
		c.Next()
	}
}

// RequirePermission 校验当前用户是否具备指定权限（须先经过 Auth 中间件）。
// 未认证返回 401，权限不足返回 403。
func RequirePermission(r *rbac.RBAC, permission string) webx.HandlerFunc {
	if r == nil || permission == "" {
		panic("authx: RBAC 与权限点不能为空")
	}
	return func(c *webx.Context) {
		claims, ok := ClaimsFrom(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, "未认证", nil)
			return
		}
		if !r.HasAnyPermission(claims.Roles, permission) {
			c.AbortWithStatusJSON(http.StatusForbidden, "无权限执行该操作", nil)
			return
		}
		c.Next()
	}
}

// RequireRole 校验当前用户是否具备指定角色（须先经过 Auth 中间件）。
func RequireRole(r *rbac.RBAC, role string) webx.HandlerFunc {
	if r == nil || role == "" {
		panic("authx: RBAC 与角色不能为空")
	}
	return func(c *webx.Context) {
		claims, ok := ClaimsFrom(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, "未认证", nil)
			return
		}
		for _, have := range claims.Roles {
			if have == role {
				c.Next()
				return
			}
		}
		c.AbortWithStatusJSON(http.StatusForbidden, "无权限执行该操作", nil)
	}
}

// CSRF 构造双提交 Cookie 校验中间件：非安全方法要求请求头与 Cookie 一致。
func CSRF(cookieName, headerName string, skipMethods ...string) webx.HandlerFunc {
	if cookieName == "" || headerName == "" {
		panic("authx: CSRF Cookie 与请求头名称不能为空")
	}
	skip := make(map[string]bool, len(skipMethods)+3)
	skip[http.MethodGet] = true
	skip[http.MethodHead] = true
	skip[http.MethodOptions] = true
	for _, m := range skipMethods {
		skip[strings.ToUpper(m)] = true
	}
	return func(c *webx.Context) {
		if skip[c.Request().Method] {
			c.Next()
			return
		}
		cookie, err := c.Cookie(cookieName)
		if err != nil || cookie.Value == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, "CSRF 校验失败", nil)
			return
		}
		if cookie.Value != c.GetHeader(headerName) {
			c.AbortWithStatusJSON(http.StatusForbidden, "CSRF 校验失败", nil)
			return
		}
		c.Next()
	}
}

// ClaimsFrom 从上下文读取已认证用户的令牌载荷。
func ClaimsFrom(c *webx.Context) (token.Claims, bool) {
	v, ok := c.Get(ctxKeyClaims)
	if !ok {
		return token.Claims{}, false
	}
	claims, ok := v.(token.Claims)
	return claims, ok
}

// UserID 返回已认证用户主体标识（未认证时为空字符串）。
func UserID(c *webx.Context) string {
	return c.GetString(ctxKeyUserID)
}

// bearerToken 从 Authorization 头提取 Bearer 令牌。
func bearerToken(header string) (string, bool) {
	raw, ok := strings.CutPrefix(header, "Bearer ")
	if !ok || raw == "" {
		return "", false
	}
	return strings.TrimSpace(raw), true
}
