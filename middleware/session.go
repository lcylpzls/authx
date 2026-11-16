package middleware

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/authx/session"
	"github.com/lcylpzls/cryptox"
	"github.com/lcylpzls/logx"
)

const (
	minSessionSignKey   = 16  // 会话签名密钥最短长度
	maxSessionCookieLen = 512 // 会话 Cookie 值长度上限
)

// sessionOptions 会话中间件配置。
type sessionOptions struct {
	idleTTL     time.Duration
	absoluteTTL time.Duration
	secure      bool
	httpOnly    bool
	path        string
	sameSite    http.SameSite
	logger      logx.Logger
	now         func() time.Time
	err         ErrorHandler
	signKey     []byte
}

// SessionOption 会话中间件配置项。
type SessionOption func(*sessionOptions)

// WithSessionTTL 设置会话空闲有效期（必须为正）；活跃请求会刷新该期限。
func WithSessionTTL(ttl time.Duration) SessionOption {
	return func(o *sessionOptions) { o.idleTTL = ttl }
}

// WithSessionAbsoluteTTL 设置从会话创建时起算的绝对有效期（必须为正）。
// 活跃请求只刷新空闲期限，不能突破绝对期限。
func WithSessionAbsoluteTTL(ttl time.Duration) SessionOption {
	return func(o *sessionOptions) { o.absoluteTTL = ttl }
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
func Session(store session.Store, cookieName string, opts ...SessionOption) func(http.Handler) http.Handler {
	if store == nil || cookieName == "" {
		panic("authx: 会话存储与 Cookie 名不能为空")
	}
	o := &sessionOptions{
		idleTTL:  24 * time.Hour,
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
	if o.idleTTL <= 0 {
		panic("authx: 会话空闲有效期必须为正")
	}
	if o.absoluteTTL < 0 {
		panic("authx: 会话绝对有效期不能为负")
	}
	if o.now == nil {
		o.now = time.Now
	}
	lifetime := session.Lifetime{IdleTTL: o.idleTTL, AbsoluteTTL: o.absoluteTTL}
	if lifetime.AbsoluteTTL > 0 {
		if _, ok := store.(session.ExpiryStore); !ok {
			panic("authx: 会话存储未实现 ExpiryStore，无法启用绝对期限")
		}
	}
	cfg := &sessionConfig{store: store, cookieName: cookieName, lifetime: lifetime, secure: o.secure,
		httpOnly: o.httpOnly, path: o.path, sameSite: o.sameSite, now: o.now, logger: o.logger,
		signKey: o.signKey}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			sess, err := loadSession(ctx, store, r, cookieName, o.signKey)
			if err != nil {
				o.err(w, r, http.StatusInternalServerError, err)
				return
			}
			if sess.ID == "" {
				created, cerr := createSession(ctx, store, lifetime)
				if cerr != nil {
					o.err(w, r, http.StatusInternalServerError, cerr)
					return
				}
				sess = created
			}
			setSessionCookie(w, sess, cfg)
			ctx = context.WithValue(ctx, ctxKeySessionConfig, cfg)
			ctx = context.WithValue(ctx, ctxKeySession, &sess)
			next.ServeHTTP(w, r.WithContext(ctx))
			// 处理器内可能已通过 RotateSession 轮换会话，保存前重新读取最新会话。
			if p, ok := sessionPointer(ctx); ok {
				sess = *p
			}
			if sess.ID == "" {
				return // DeleteSession 已删除会话，禁止请求结束时重新保存。
			}
			if err := saveSession(ctx, store, sess, lifetime); err != nil && o.logger != nil {
				o.logger.Warn("会话保存失败", logx.Fields(
					logx.String("session_id", sess.ID),
					logx.String("error", err.Error()),
				))
			}
		})
	}
}

func createSession(
	ctx context.Context,
	store session.Store,
	lifetime session.Lifetime,
) (session.Session, error) {
	if expiry, ok := store.(session.ExpiryStore); ok {
		return expiry.CreateWithLifetime(ctx, lifetime)
	}
	return store.Create(ctx, lifetime.IdleTTL)
}

func saveSession(
	ctx context.Context,
	store session.Store,
	sess session.Session,
	lifetime session.Lifetime,
) error {
	if expiry, ok := store.(session.ExpiryStore); ok {
		return expiry.SaveWithLifetime(ctx, sess, lifetime)
	}
	return store.Save(ctx, sess, lifetime.IdleTTL)
}

func rotateSession(
	ctx context.Context,
	store session.Store,
	id string,
	lifetime session.Lifetime,
) (session.Session, error) {
	if expiry, ok := store.(session.ExpiryStore); ok {
		return expiry.RotateWithLifetime(ctx, id, lifetime)
	}
	return store.Rotate(ctx, id, lifetime.IdleTTL)
}

// sessionConfig 会话中间件配置快照（供 RotateSession 使用）。
type sessionConfig struct {
	store      session.Store
	cookieName string
	lifetime   session.Lifetime
	secure     bool
	httpOnly   bool
	path       string
	sameSite   http.SameSite
	now        func() time.Time
	logger     logx.Logger
	signKey    []byte
}

// RotateSession 轮换当前会话 ID（防会话固定攻击），并同步更新 Cookie 与上下文。
// 使用 SessionCSRFProtect 时还会轮换会话绑定的 CSRF 令牌，应在登录或改密后调用。
// 仅在经过 Session 中间件的处理器中调用；未装配会话或读取会话失败时返回错误。
func RotateSession(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	v := ctx.Value(ctxKeySessionConfig)
	if v == nil {
		return authx.ErrSessionInvalid
	}
	cfg, ok := v.(*sessionConfig)
	if !ok {
		return authx.ErrSessionInvalid
	}
	sess, ok := SessionFrom(ctx)
	if !ok || sess.ID == "" {
		return authx.ErrSessionNotFound
	}
	csrfCfg, rotateCSRF := sessionCSRFConfigFrom(ctx)
	csrfToken := ""
	if rotateCSRF {
		var err error
		csrfToken, err = GenerateCSRFToken()
		if err != nil {
			return err
		}
	}
	rotated, err := rotateSession(ctx, cfg.store, sess.ID, cfg.lifetime)
	if err != nil {
		return err
	}
	if rotateCSRF {
		if rotated.Values == nil {
			rotated.Values = make(map[string]string)
		}
		rotated.Values[sessionCSRFTokenKey] = csrfToken
		setCSRFCookie(w, csrfCfg.options, csrfCfg.cookieName, csrfToken)
	}
	setSessionCookie(w, rotated, cfg)
	p, _ := sessionPointer(ctx)
	*p = rotated
	return nil
}

// DeleteSession 删除当前服务端会话并失效会话及会话绑定 CSRF Cookie。
// 处理函数内调用时须继续装配 Session 中间件，以阻止请求结束时重新保存会话。
func DeleteSession(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	v := ctx.Value(ctxKeySessionConfig)
	if v == nil {
		return authx.ErrSessionInvalid
	}
	cfg, ok := v.(*sessionConfig)
	if !ok || cfg == nil || cfg.store == nil {
		return authx.ErrSessionInvalid
	}
	p, ok := sessionPointer(ctx)
	if !ok || p.ID == "" {
		return authx.ErrSessionNotFound
	}
	if err := cfg.store.Delete(ctx, p.ID); err != nil {
		return err
	}
	clearSessionCookie(w, cfg)
	if csrfCfg, ok := sessionCSRFConfigFrom(ctx); ok {
		clearCSRFCookie(w, csrfCfg.options, csrfCfg.cookieName)
	}
	*p = session.Session{}
	return nil
}

// SessionFrom 从上下文读取会话。
func SessionFrom(ctx context.Context) (session.Session, bool) {
	p, ok := sessionPointer(ctx)
	if !ok || p.ID == "" {
		return session.Session{}, false
	}
	return *p, true
}

func sessionPointer(ctx context.Context) (*session.Session, bool) {
	v := ctx.Value(ctxKeySession)
	p, ok := v.(*session.Session)
	return p, ok && p != nil
}

func setSessionCookie(w http.ResponseWriter, sess session.Session, cfg *sessionConfig) {
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.cookieName,
		Value:    signedSessionValue(sess.ID, cfg.signKey),
		Path:     cfg.path,
		Secure:   cfg.secure,
		HttpOnly: cfg.httpOnly,
		SameSite: cfg.sameSite,
		Expires:  sessionCookieExpiry(sess, cfg),
	})
}

func sessionCookieExpiry(sess session.Session, cfg *sessionConfig) time.Time {
	expires := cfg.now().Add(cfg.lifetime.IdleTTL)
	if !sess.AbsoluteExpiresAt.IsZero() && sess.AbsoluteExpiresAt.Before(expires) {
		expires = sess.AbsoluteExpiresAt
	}
	return expires
}

func clearSessionCookie(w http.ResponseWriter, cfg *sessionConfig) {
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.cookieName,
		Value:    "",
		Path:     cfg.path,
		Secure:   cfg.secure,
		HttpOnly: cfg.httpOnly,
		SameSite: cfg.sameSite,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
	})
}

// loadSession 读取 Cookie 并加载会话；缺失或过期返回空会话（由调用方新建）。
func loadSession(ctx context.Context, store session.Store, r *http.Request, cookieName string, signKey []byte) (session.Session, error) {
	cookie, err := r.Cookie(cookieName)
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
	// key 非空时 SignHMAC 不会失败。
	sig, _ := cryptox.SignHMAC(key, []byte(id))
	return id + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// verifySessionCookie 校验签名并返回会话 ID；格式非法或签名不匹配返回 false。
func verifySessionCookie(value string, key []byte) (string, bool) {
	idx := strings.LastIndex(value, ".")
	if idx <= 0 || idx == len(value)-1 {
		return "", false
	}
	id, sig := value[:idx], value[idx+1:]
	// key 非空时 SignHMAC 不会失败。
	want, _ := cryptox.SignHMAC(key, []byte(id))
	wantEnc := base64.RawURLEncoding.EncodeToString(want)
	if !cryptox.ConstantTimeEquals([]byte(sig), []byte(wantEnc)) {
		return "", false
	}
	return id, true
}
