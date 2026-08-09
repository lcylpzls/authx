// Package middleware 提供 webx 认证、授权与 CSRF 中间件。
package middleware

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/authx/rbac"
	"github.com/lcylpzls/authx/token"
	"github.com/lcylpzls/errx"
	"github.com/lcylpzls/webx"
)

const (
	ctxKeyClaims       = "authx_claims"
	ctxKeyUserID       = "authx_user_id"
	maxBearerLength    = 4096 // Bearer 令牌长度上限（防超长头 DoS）
	maxCSRFTokenLength = 256  // CSRF 令牌长度上限（防超长值 DoS）
	csrfTokenBytes     = 32
	defaultCSRFTTL     = 24 * time.Hour
)

// randRead 可替换的随机源，便于测试注入失败场景。
var randRead = rand.Read

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
	challenge := "Bearer realm=" + quoteRealm(o.realm)
	return func(c *webx.Context) {
		raw, ok := bearerToken(c.GetHeader("Authorization"))
		if !ok {
			c.Header("WWW-Authenticate", challenge)
			c.AbortWithStatusJSON(http.StatusUnauthorized, "未认证", nil)
			return
		}
		claims, err := signer.Parse(raw)
		if err != nil {
			c.Header("WWW-Authenticate", challenge)
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
		if err != nil || !ValidateCSRFToken(cookie.Value, c.GetHeader(headerName)) {
			c.AbortWithStatusJSON(http.StatusForbidden, "CSRF 校验失败", nil)
			return
		}
		c.Next()
	}
}

// csrfOptions 双提交 CSRF 中间件配置。
type csrfOptions struct {
	secure   bool
	httpOnly bool
	path     string
	sameSite http.SameSite
	ttl      time.Duration
	now      func() time.Time
}

// CSRFOption 双提交 CSRF 中间件配置项。
type CSRFOption func(*csrfOptions)

// WithCSRFSecure 设置 CSRF Cookie Secure 标记。
func WithCSRFSecure(secure bool) CSRFOption {
	return func(o *csrfOptions) { o.secure = secure }
}

// WithCSRFHTTPOnly 设置 CSRF Cookie HttpOnly 标记（默认 false，前端脚本需读取）。
func WithCSRFHTTPOnly(httpOnly bool) CSRFOption {
	return func(o *csrfOptions) { o.httpOnly = httpOnly }
}

// WithCSRFPath 设置 CSRF Cookie 路径。
func WithCSRFPath(path string) CSRFOption {
	return func(o *csrfOptions) { o.path = path }
}

// WithCSRFSameSite 设置 CSRF Cookie SameSite 策略。
func WithCSRFSameSite(sameSite http.SameSite) CSRFOption {
	return func(o *csrfOptions) { o.sameSite = sameSite }
}

// WithCSRFTTL 设置 CSRF Cookie 有效期（必须为正）。
func WithCSRFTTL(ttl time.Duration) CSRFOption {
	return func(o *csrfOptions) { o.ttl = ttl }
}

// WithCSRFClock 注入时间源（测试用）。
func WithCSRFClock(now func() time.Time) CSRFOption {
	return func(o *csrfOptions) { o.now = now }
}

// GenerateCSRFToken 生成 32 字节随机 base64url 令牌。
func GenerateCSRFToken() (string, error) {
	b := make([]byte, csrfTokenBytes)
	if _, err := randRead(b); err != nil {
		return "", errx.Wrap(err, errx.KindUnavailable, authx.CodeCSRFGenerationFailed, "CSRF 令牌生成失败")
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ValidateCSRFToken 常量时间比较 Cookie 与请求头令牌；超长或空值直接拒绝。
func ValidateCSRFToken(cookie, header string) bool {
	if cookie == "" || header == "" ||
		len(cookie) > maxCSRFTokenLength || len(header) > maxCSRFTokenLength {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie), []byte(header)) == 1
}

// CSRFProtect 构造双提交 Cookie 中间件：安全方法放行并保证已种令牌，
// 非安全方法要求请求头与 Cookie 令牌一致（常量时间比较）。
func CSRFProtect(cookieName, headerName string, opts ...CSRFOption) webx.HandlerFunc {
	if cookieName == "" || headerName == "" {
		panic("authx: CSRF Cookie 与请求头名称不能为空")
	}
	o := &csrfOptions{
		secure:   true,
		httpOnly: false,
		path:     "/",
		sameSite: http.SameSiteLaxMode,
		ttl:      defaultCSRFTTL,
		now:      time.Now,
	}
	for _, opt := range opts {
		opt(o)
	}
	if o.ttl <= 0 {
		panic("authx: CSRF 有效期必须为正")
	}
	if o.now == nil {
		o.now = time.Now
	}
	skip := map[string]bool{
		http.MethodGet:     true,
		http.MethodHead:    true,
		http.MethodOptions: true,
	}
	return func(c *webx.Context) {
		if cookie, err := c.Cookie(cookieName); err != nil || cookie.Value == "" {
			token, terr := GenerateCSRFToken()
			if terr != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, "CSRF 初始化失败", nil)
				return
			}
			c.SetCookie(&http.Cookie{
				Name:     cookieName,
				Value:    token,
				Path:     o.path,
				Secure:   o.secure,
				HttpOnly: o.httpOnly,
				SameSite: o.sameSite,
				Expires:  o.now().Add(o.ttl),
			})
		}
		if skip[c.Request().Method] {
			c.Next()
			return
		}
		cookieValue := ""
		if cookie, err := c.Cookie(cookieName); err == nil {
			cookieValue = cookie.Value
		}
		if !ValidateCSRFToken(cookieValue, c.GetHeader(headerName)) {
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
	if !ok || raw == "" || len(raw) > maxBearerLength {
		return "", false
	}
	return strings.TrimSpace(raw), true
}

// quoteRealm 按 RFC 7235 转义 WWW-Authenticate realm 参数。
func quoteRealm(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}
