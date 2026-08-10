package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/authx/session"
	"github.com/lcylpzls/logx"
	"github.com/lcylpzls/webx/v2"
)

const (
	ctxKeySession       = "authx_session"
	ctxKeySessionConfig = "authx_session_config"
	minSessionSignKey   = 16  // 会话签名密钥最短长度
	maxSessionCookieLen = 512 // 会话 Cookie 值长度上限
)

// sessionOptions 会话中间件配置。
type sessionOptions struct {
	ttl      time.Duration
	secure   bool
	httpOnly bool
	path     string
	sameSite http.SameSite
	logger   logx.Logger
	now      func() time.Time
	err      ErrorHandler
	signKey  []byte
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

// WithSessionLogger 注入日志器：会话保存失败时记录告警（nil 表示不记录）。
func WithSessionLogger(logger logx.Logger) SessionOption {
	return func(o *sessionOptions) { o.logger = logger }
}

// WithSessionClock 注入时间源（测试用）。
func WithSessionClock(now func() time.Time) SessionOption {
	return func(o *sessionOptions) { o.now = now }
}

// WithSessionErrorHandler 自定义会话服务错误响应处理器。
func WithSessionErrorHandler(handler ErrorHandler) SessionOption {
	return func(o *sessionOptions) {
		if handler == nil {
			panic("authx: 会话错误处理器不能为空")
		}
		o.err = handler
	}
}

// WithSessionSigningKey 启用会话 Cookie 值 HMAC-SHA256 签名（防篡改/伪造会话 ID）。
// 密钥至少 16 字节；多实例部署时各实例必须使用同一密钥。
func WithSessionSigningKey(key []byte) SessionOption {
	return func(o *sessionOptions) {
		if len(key) < minSessionSignKey {
			panic("authx: 会话签名密钥至少 16 字节")
		}
		o.signKey = append([]byte(nil), key...)
	}
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
		now:      time.Now,
		err:      DefaultErrorHandler,
	}
	for _, opt := range opts {
		opt(o)
	}
	if o.ttl <= 0 {
		panic("authx: 会话有效期必须为正")
	}
	if o.now == nil {
		o.now = time.Now
	}
	cfg := &sessionConfig{store: store, cookieName: cookieName, ttl: o.ttl, secure: o.secure,
		httpOnly: o.httpOnly, path: o.path, sameSite: o.sameSite, now: o.now, logger: o.logger,
		signKey: o.signKey}
	return func(c *webx.Context) {
		ctx := c.Request().Context()
		sess, err := loadSession(ctx, store, c, cookieName, o.signKey)
		if err != nil {
			o.err(c, http.StatusInternalServerError, err)
			return
		}
		if sess.ID == "" {
			created, cerr := store.Create(ctx, o.ttl)
			if cerr != nil {
				o.err(c, http.StatusInternalServerError, cerr)
				return
			}
			sess = created
			c.SetCookie(&http.Cookie{
				Name:     cookieName,
				Value:    signedSessionValue(sess.ID, o.signKey),
				Path:     o.path,
				Secure:   o.secure,
				HttpOnly: o.httpOnly,
				SameSite: o.sameSite,
				Expires:  o.now().Add(o.ttl),
			})
		}
		c.Set(ctxKeySessionConfig, cfg)
		c.Set(ctxKeySession, sess)
		c.Next()
		// 处理器内可能已通过 RotateSession 轮换会话，保存前重新读取最新会话。
		if latest, ok := c.Get(ctxKeySession); ok {
			if s, ok := latest.(session.Session); ok && s.ID != "" {
				sess = s
			}
		}
		if err := store.Save(ctx, sess, o.ttl); err != nil && o.logger != nil {
			o.logger.Warn("会话保存失败", logx.Fields(
				logx.String("session_id", sess.ID),
				logx.String("error", err.Error()),
			))
		}
	}
}

// sessionConfig 会话中间件配置快照（供 RotateSession 使用）。
type sessionConfig struct {
	store      session.Store
	cookieName string
	ttl        time.Duration
	secure     bool
	httpOnly   bool
	path       string
	sameSite   http.SameSite
	now        func() time.Time
	logger     logx.Logger
	signKey    []byte
}

// RotateSession 轮换当前会话 ID（防会话固定攻击），并同步更新 Cookie 与上下文。
// 仅在经过 Session 中间件的处理器中调用；未装配会话或读取会话失败时返回错误。
func RotateSession(c *webx.Context) error {
	v, ok := c.Get(ctxKeySessionConfig)
	if !ok {
		return authx.ErrSessionInvalid
	}
	cfg, ok := v.(*sessionConfig)
	if !ok {
		return authx.ErrSessionInvalid
	}
	sess, ok := SessionFrom(c)
	if !ok || sess.ID == "" {
		return authx.ErrSessionNotFound
	}
	rotated, err := cfg.store.Rotate(c.Request().Context(), sess.ID, cfg.ttl)
	if err != nil {
		return err
	}
	c.SetCookie(&http.Cookie{
		Name:     cfg.cookieName,
		Value:    signedSessionValue(rotated.ID, cfg.signKey),
		Path:     cfg.path,
		Secure:   cfg.secure,
		HttpOnly: cfg.httpOnly,
		SameSite: cfg.sameSite,
		Expires:  cfg.now().Add(cfg.ttl),
	})
	c.Set(ctxKeySession, rotated)
	return nil
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
func loadSession(ctx context.Context, store session.Store, c *webx.Context, cookieName string, signKey []byte) (session.Session, error) {
	cookie, err := c.Cookie(cookieName)
	if err != nil || cookie.Value == "" || len(cookie.Value) > maxSessionCookieLen {
		return session.Session{}, nil
	}
	id := cookie.Value
	if len(signKey) > 0 {
		valid, ok := verifySessionCookie(cookie.Value, signKey)
		if !ok {
			return session.Session{}, nil // 签名无效视为无会话（防伪造）。
		}
		id = valid
	}
	sess, err := store.Get(ctx, id)
	if err == nil {
		return sess, nil
	}
	if errors.Is(err, authx.ErrSessionNotFound) {
		return session.Session{}, nil
	}
	return session.Session{}, err
}

// signedSessionValue 为会话 ID 附加 HMAC-SHA256 签名（无密钥时原样返回）。
func signedSessionValue(id string, key []byte) string {
	if len(key) == 0 {
		return id
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(id))
	return id + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// verifySessionCookie 校验签名并返回会话 ID；格式非法或签名不匹配返回 false。
func verifySessionCookie(value string, key []byte) (string, bool) {
	idx := strings.LastIndex(value, ".")
	if idx <= 0 || idx == len(value)-1 {
		return "", false
	}
	id, sig := value[:idx], value[idx+1:]
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(id))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		return "", false
	}
	return id, true
}
