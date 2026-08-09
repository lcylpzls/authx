package middleware

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/authx/session"
	"github.com/lcylpzls/webx"
)

const ctxKeySession = "authx_session"

// sessionOptions 会话中间件配置。
type sessionOptions struct {
	ttl      time.Duration
	secure   bool
	httpOnly bool
	path     string
	sameSite http.SameSite
}

// SessionOption 会话中间件配置项。
type SessionOption func(*sessionOptions)

// WithSessionTTL 设置会话有效期（必须为正）。
func WithSessionTTL(ttl time.Duration) SessionOption {
	return func(o *sessionOptions) { o.ttl = ttl }
}

// WithSessionSecure 设置 Cookie Secure 标记。
func WithSessionSecure(secure bool) SessionOption {
	return func(o *sessionOptions) { o.secure = secure }
}

// WithSessionHTTPOnly 设置 Cookie HttpOnly 标记。
func WithSessionHTTPOnly(httpOnly bool) SessionOption {
	return func(o *sessionOptions) { o.httpOnly = httpOnly }
}

// WithSessionPath 设置 Cookie 路径。
func WithSessionPath(path string) SessionOption {
	return func(o *sessionOptions) { o.path = path }
}

// WithSessionSameSite 设置 Cookie SameSite 策略。
func WithSessionSameSite(sameSite http.SameSite) SessionOption {
	return func(o *sessionOptions) { o.sameSite = sameSite }
}

// Session 构造会话中间件：读取/创建会话，请求结束后自动保存。
// 处理器内通过 SessionFrom 读取，修改 Values 后由中间件统一落库。
func Session(store session.Store, cookieName string, opts ...SessionOption) webx.HandlerFunc {
	if store == nil || cookieName == "" {
		panic("authx: 会话存储与 Cookie 名不能为空")
	}
	o := &sessionOptions{
		ttl:      24 * time.Hour,
		secure:   true,
		httpOnly: true,
		path:     "/",
		sameSite: http.SameSiteLaxMode,
	}
	for _, opt := range opts {
		opt(o)
	}
	if o.ttl <= 0 {
		panic("authx: 会话有效期必须为正")
	}
	return func(c *webx.Context) {
		ctx := c.Request().Context()
		sess, err := loadSession(ctx, store, c, cookieName)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, "会话服务异常", nil)
			return
		}
		if sess.ID == "" {
			created, cerr := store.Create(ctx, o.ttl)
			if cerr != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, "会话创建失败", nil)
				return
			}
			sess = created
			c.SetCookie(&http.Cookie{
				Name:     cookieName,
				Value:    sess.ID,
				Path:     o.path,
				Secure:   o.secure,
				HttpOnly: o.httpOnly,
				SameSite: o.sameSite,
				Expires:  time.Now().Add(o.ttl),
			})
		}
		c.Set(ctxKeySession, sess)
		c.Next()
		_ = store.Save(ctx, sess, o.ttl)
	}
}

// SessionFrom 从上下文读取会话。
func SessionFrom(c *webx.Context) (session.Session, bool) {
	v, ok := c.Get(ctxKeySession)
	if !ok {
		return session.Session{}, false
	}
	sess, ok := v.(session.Session)
	return sess, ok
}

// loadSession 读取 Cookie 并加载会话；缺失或过期返回空会话（由调用方新建）。
func loadSession(ctx context.Context, store session.Store, c *webx.Context, cookieName string) (session.Session, error) {
	cookie, err := c.Cookie(cookieName)
	if err != nil || cookie.Value == "" {
		return session.Session{}, nil
	}
	sess, err := store.Get(ctx, cookie.Value)
	if err == nil {
		return sess, nil
	}
	if errors.Is(err, authx.ErrSessionNotFound) {
		return session.Session{}, nil
	}
	return session.Session{}, err
}
