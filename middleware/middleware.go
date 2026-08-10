// Package middleware 提供 webx 认证、授权与 CSRF 中间件。
package middleware

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/authx/rbac"
	"github.com/lcylpzls/authx/token"
	"github.com/lcylpzls/cryptox"
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
	maxOriginLength    = 2048 // Origin/Referer 长度上限
)

// randRead 可替换的随机源，便于测试注入失败场景。
var randRead = cryptox.RandomBytes

// ErrorResponse 中间件统一 JSON 错误响应体（errx 语义）。
type ErrorResponse struct {
	// Code 错误码（如 authx_token_invalid）。
	Code string `json:"code"`
	// Kind 错误分类（如 unauthorized / forbidden / unavailable）。
	Kind string `json:"kind"`
	// Message 面向用户的错误描述。
	Message string `json:"message"`
}

// ErrorHandler 自定义错误响应处理器；status 为建议 HTTP 状态码。
type ErrorHandler func(c *webx.Context, status int, err error)

// DefaultErrorHandler 输出结构化 JSON 错误响应。
func DefaultErrorHandler(c *webx.Context, status int, err error) {
	resp := errorResponseFrom(err)
	c.AbortWithStatusJSON(status, resp.Message, resp)
}

// errorResponseFrom 从错误提取 errx 语义；非 errx 错误回退 unknown。
func errorResponseFrom(err error) ErrorResponse {
	resp := ErrorResponse{Message: "内部错误"}
	if err != nil {
		resp.Message = err.Error()
	}
	if code, ok := errx.CodeOf(err); ok {
		resp.Code = string(code)
	}
	resp.Kind = errx.KindOf(err).String()
	return resp
}

// authOptions 认证中间件配置。
type authOptions struct {
	realm        string
	errorHandler ErrorHandler
}

// Option 认证中间件配置项。
type Option func(*authOptions)

// WithRealm 设置 WWW-Authenticate 提示域。
func WithRealm(realm string) Option {
	return func(o *authOptions) { o.realm = realm }
}

// WithAuthErrorHandler 自定义认证失败响应处理器。
func WithAuthErrorHandler(handler ErrorHandler) Option {
	return func(o *authOptions) {
		if handler == nil {
			panic("authx: 认证错误处理器不能为空")
		}
		o.errorHandler = handler
	}
}

// Auth 构造 Bearer Token 认证中间件：解析并校验令牌，注入用户身份。
// 校验失败返回 401 标准响应；成功后调用 c.Next() 继续处理链。
func Auth(signer *token.Signer, opts ...Option) webx.HandlerFunc {
	if signer == nil {
		panic("authx: 签发器不能为空")
	}
	o := &authOptions{realm: "api", errorHandler: DefaultErrorHandler}
	for _, opt := range opts {
		opt(o)
	}
	challenge := "Bearer realm=" + quoteRealm(o.realm)
	return func(c *webx.Context) {
		raw, ok := bearerToken(c.GetHeader("Authorization"))
		if !ok {
			c.Header("WWW-Authenticate", challenge)
			o.errorHandler(c, http.StatusUnauthorized, authx.ErrTokenMissing)
			return
		}
		claims, err := signer.Parse(raw)
		if err != nil {
			c.Header("WWW-Authenticate", challenge)
			o.errorHandler(c, http.StatusUnauthorized, err)
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
			DefaultErrorHandler(c, http.StatusUnauthorized, authx.ErrTokenMissing)
			return
		}
		if !r.HasAnyPermission(claims.Roles, permission) {
			DefaultErrorHandler(c, http.StatusForbidden, authx.ErrForbidden)
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
			DefaultErrorHandler(c, http.StatusUnauthorized, authx.ErrTokenMissing)
			return
		}
		for _, have := range claims.Roles {
			if have == role {
				c.Next()
				return
			}
		}
		DefaultErrorHandler(c, http.StatusForbidden, authx.ErrForbidden)
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
			DefaultErrorHandler(c, http.StatusForbidden, authx.ErrCSRFMismatch)
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
	err      ErrorHandler
	origins  []string
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

// WithCSRFErrorHandler 自定义 CSRF 校验失败响应处理器。
func WithCSRFErrorHandler(handler ErrorHandler) CSRFOption {
	return func(o *csrfOptions) {
		if handler == nil {
			panic("authx: CSRF 错误处理器不能为空")
		}
		o.err = handler
	}
}

// WithCSRFAllowedOrigins 设置允许的跨站来源（Origin 精确匹配；
// 请求无 Origin 头时回退校验 Referer 的 scheme://host）。
func WithCSRFAllowedOrigins(origins ...string) CSRFOption {
	return func(o *csrfOptions) {
		cleaned := make([]string, 0, len(origins))
		for _, x := range origins {
			x = strings.TrimRight(x, "/")
			if x != "" {
				cleaned = append(cleaned, x)
			}
		}
		o.origins = cleaned
	}
}

// GenerateCSRFToken 生成 32 字节随机 base64url 令牌。
func GenerateCSRFToken() (string, error) {
	b, err := randRead(csrfTokenBytes)
	if err != nil {
		return "", errx.WrapCode(err, authx.CodeCSRFGenerationFailed, "CSRF 令牌生成失败")
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ValidateCSRFToken 常量时间比较 Cookie 与请求头令牌；超长或空值直接拒绝。
func ValidateCSRFToken(cookie, header string) bool {
	if cookie == "" || header == "" ||
		len(cookie) > maxCSRFTokenLength || len(header) > maxCSRFTokenLength {
		return false
	}
	return cryptox.ConstantTimeEquals([]byte(cookie), []byte(header))
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
		err:      DefaultErrorHandler,
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
				o.err(c, http.StatusInternalServerError, authx.ErrCSRFGenerationFailed)
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
		if !o.originAllowed(c) {
			o.err(c, http.StatusForbidden, authx.ErrCSRFMismatch)
			return
		}
		cookieValue := ""
		if cookie, err := c.Cookie(cookieName); err == nil {
			cookieValue = cookie.Value
		}
		if !ValidateCSRFToken(cookieValue, c.GetHeader(headerName)) {
			o.err(c, http.StatusForbidden, authx.ErrCSRFMismatch)
			return
		}
		c.Next()
	}
}

// originAllowed 校验非安全请求的来源；未配置允许列表时直接放行。
func (o *csrfOptions) originAllowed(c *webx.Context) bool {
	if len(o.origins) == 0 {
		return true
	}
	if origin := c.GetHeader("Origin"); origin != "" {
		if len(origin) > maxOriginLength {
			return false
		}
		for _, allowed := range o.origins {
			if origin == allowed {
				return true
			}
		}
		return false
	}
	if ref := c.GetHeader("Referer"); ref != "" {
		if len(ref) > maxOriginLength {
			return false
		}
		u, err := url.Parse(ref)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return false
		}
		base := u.Scheme + "://" + u.Host
		for _, allowed := range o.origins {
			if base == allowed {
				return true
			}
		}
	}
	return false
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
