package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	testx "github.com/lcylpzls/testx"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/authx/session"
	"github.com/lcylpzls/errx"
	"github.com/lcylpzls/logx"
)

// TestSessionPanics 覆盖会话中间件 panic 分支。
func TestSessionPanics(t *testing.T) {
	store := session.NewMemoryStore(nil)
	for name, fn := range map[string]func(){
		"空存储":        func() { _ = Session(nil, "sid") },
		"空 Cookie 名": func() { _ = Session(store, "") },
		"零空闲 TTL":    func() { _ = Session(store, "sid", WithSessionTTL(0)) },
		"负绝对 TTL":    func() { _ = Session(store, "sid", WithSessionAbsoluteTTL(-1)) },
		"旧存储绝对期限": func() {
			_ = Session(&failStore{}, "sid", WithSessionAbsoluteTTL(time.Hour))
		},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("%s 应 panic", name)
				}
			}()
			fn()
		}()
	}
}

// runSessionChain 执行会话中间件链并返回请求上下文。
func runSessionChain(t *testing.T, mws ...func(http.Handler) http.Handler) (*httptest.ResponseRecorder, *http.Request) {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	var h http.Handler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	h.ServeHTTP(w, req)
	return w, req
}

// TestSessionFlow 覆盖会话中间件主流程。
func TestSessionFlow(t *testing.T) {
	store := session.NewMemoryStore(nil)
	mw := Session(store, "sid", WithSessionTTL(time.Hour), WithSessionSecure(false))
	handled := false
	var sid string
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handled = true
		s, ok := SessionFrom(r.Context())
		testx.RequireTrue(t, ok)
		sid = s.ID
	})).ServeHTTP(rec, req)
	testx.RequireTrue(t, handled)
	testx.RequireNotEqual(t, sid, "")
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 || cookies[0].Name != "sid" {
		t.Fatal("应种会话 Cookie")
	}

	// 带 Cookie 再次访问 → 读取既有会话。
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req2.AddCookie(cookies[0])
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, ok := SessionFrom(r.Context())
		testx.RequireTrue(t, ok)
		testx.RequireEqual(t, s.ID, sid)
	})).ServeHTTP(rec2, req2)
}

// TestSessionNoCookie 覆盖无 Cookie 时上下文无会话。
func TestSessionNoCookie(t *testing.T) {
	_, req := runSessionChain(t)
	if _, ok := SessionFrom(req.Context()); ok {
		t.Fatal("未装配会话中间件不应有会话")
	}
}

// TestRotateSession 覆盖会话轮换。
func TestRotateSession(t *testing.T) {
	store := session.NewMemoryStore(nil)
	mw := Session(store, "sid", WithSessionTTL(time.Hour), WithSessionSecure(false))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	var oldID, newID string
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := SessionFrom(r.Context())
		oldID = s.ID
		testx.RequireNoError(t, RotateSession(w, r))
		s2, _ := SessionFrom(r.Context())
		newID = s2.ID
	})).ServeHTTP(rec, req)
	testx.RequireNotEqual(t, oldID, "")
	testx.RequireNotEqual(t, newID, "")
	testx.RequireNotEqual(t, oldID, newID)
}

// TestRotateSessionNotInstalled 覆盖未装配会话中间件时轮换失败。
func TestRotateSessionNotInstalled(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	if err := RotateSession(rec, req); !errors.Is(err, authx.ErrSessionInvalid) {
		t.Fatalf("应返回 ErrSessionInvalid：%v", err)
	}
}

// TestSessionSaveFailure 覆盖保存失败告警路径。
func TestSessionSaveFailure(t *testing.T) {
	fail := &failStore{}
	lg, _ := logx.NewBuilder().EnableConsole(logx.OffLevel).Build()
	mw := Session(fail, "sid", WithSessionTTL(time.Hour), WithSessionSecure(false),
		WithSessionLogger(lg))
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rec,
		httptest.NewRequest(http.MethodGet, "/ping", nil))
}

// TestSessionSigningKey 覆盖签名密钥校验。
func TestSessionSigningKey(t *testing.T) {
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("短密钥应 panic")
			}
		}()
		WithSessionSigningKey([]byte("short"))(&sessionOptions{})
	}()
	_ = WithSessionSigningKey(make([]byte, 32))
}

// TestSessionOptions 覆盖会话配置项。
func TestSessionOptions(t *testing.T) {
	o := &sessionOptions{}
	WithSessionTTL(time.Hour)(o)
	WithSessionAbsoluteTTL(2 * time.Hour)(o)
	WithSessionSecure(false)(o)
	WithSessionHTTPOnly(false)(o)
	WithSessionPath("/x")(o)
	WithSessionSameSite(http.SameSiteStrictMode)(o)
	WithSessionLogger(nil)(o)
	WithSessionClock(time.Now)(o)
	WithSessionErrorHandler(DefaultErrorHandler)(o)
	WithSessionSigningKey(make([]byte, 32))(o)
	testx.RequireEqual(t, o.path, "/x")
	testx.RequireEqual(t, o.absoluteTTL, 2*time.Hour)
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("nil 会话错误处理器应 panic")
			}
		}()
		WithSessionErrorHandler(nil)(&sessionOptions{})
	}()
}

// failStore 是恒失败的会话存储。
type failStore struct{}

func (f *failStore) Create(ctx context.Context, ttl time.Duration) (session.Session, error) {
	return session.Session{ID: "new", Values: map[string]string{}}, nil
}
func (f *failStore) Get(ctx context.Context, id string) (session.Session, error) {
	return session.Session{}, authx.ErrSessionNotFound
}
func (f *failStore) Save(ctx context.Context, s session.Session, ttl time.Duration) error {
	return errors.New("保存失败")
}
func (f *failStore) Delete(ctx context.Context, id string) error { return nil }
func (f *failStore) Rotate(ctx context.Context, id string, ttl time.Duration) (session.Session, error) {
	return session.Session{ID: "rotated", Values: map[string]string{}}, nil
}

// TestSessionLifetimeAndRefresh 覆盖空闲续期、绝对上限与 Cookie 刷新。
func TestSessionLifetimeAndRefresh(t *testing.T) {
	now := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	store := session.NewMemoryStore(func() time.Time { return now })
	mw := Session(store, "sid",
		WithSessionTTL(30*time.Minute),
		WithSessionAbsoluteTTL(time.Hour),
		WithSessionSecure(false),
		WithSessionClock(func() time.Time { return now }))

	var sid string
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(
		rec, httptest.NewRequest(http.MethodGet, "/ping", nil))
	sessionCookie := cookieByName(rec.Result().Cookies(), "sid")
	testx.RequireNotNil(t, sessionCookie)
	sid = sessionCookie.Value
	testx.RequireEqual(t, sessionCookie.Expires, now.Add(30*time.Minute))

	now = now.Add(20 * time.Minute)
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req2.AddCookie(sessionCookie)
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec2, req2)
	refreshed := cookieByName(rec2.Result().Cookies(), "sid")
	testx.RequireNotNil(t, refreshed)
	testx.RequireEqual(t, refreshed.Expires, now.Add(30*time.Minute))
	got, err := store.Get(context.Background(), sid)
	testx.RequireNoError(t, err)
	testx.RequireEqual(t, got.AbsoluteExpiresAt, time.Date(2026, 11, 16, 11, 0, 0, 0, time.UTC))

	now = now.Add(41 * time.Minute)
	rec3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req3.AddCookie(sessionCookie)
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec3, req3)
	replaced := cookieByName(rec3.Result().Cookies(), "sid")
	testx.RequireNotNil(t, replaced)
	testx.RequireNotEqual(t, replaced.Value, sessionCookie.Value)
}

// TestDeleteSession 覆盖登出删除与 Cookie 失效。
func TestDeleteSession(t *testing.T) {
	store := session.NewMemoryStore(nil)
	mw := Session(store, "sid", WithSessionSecure(false))
	var oldID string
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := SessionFrom(r.Context())
		testx.RequireTrue(t, ok)
		oldID = sess.ID
		testx.RequireNoError(t, DeleteSession(w, r))
		if _, ok := SessionFrom(r.Context()); ok {
			t.Fatal("删除后上下文不应保留会话")
		}
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/logout", nil))
	testx.RequireNotEqual(t, oldID, "")
	if _, err := store.Get(context.Background(), oldID); !errors.Is(err, authx.ErrSessionNotFound) {
		t.Fatalf("服务端会话应已删除：%v", err)
	}
	deleted := lastCookieByName(rec.Result().Cookies(), "sid")
	testx.RequireNotNil(t, deleted)
	testx.RequireEqual(t, deleted.Value, "")
	testx.RequireEqual(t, deleted.MaxAge, -1)
}

// TestDeleteSessionErrors 覆盖未装配、类型错误、无会话与存储失败。
func TestDeleteSessionErrors(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	if err := DeleteSession(rec, req); !errors.Is(err, authx.ErrSessionInvalid) {
		t.Fatalf("未装配会话应报参数错误：%v", err)
	}

	ctx := context.WithValue(req.Context(), ctxKeySessionConfig, "bad")
	if err := DeleteSession(rec, req.WithContext(ctx)); !errors.Is(err, authx.ErrSessionInvalid) {
		t.Fatalf("配置类型错误应报参数错误：%v", err)
	}

	cfg := &sessionConfig{store: session.NewMemoryStore(nil), cookieName: "sid"}
	ctx = context.WithValue(req.Context(), ctxKeySessionConfig, cfg)
	if err := DeleteSession(rec, req.WithContext(ctx)); !errors.Is(err, authx.ErrSessionNotFound) {
		t.Fatalf("无会话应报不存在：%v", err)
	}

	fail := &deleteFailStore{}
	cfg = &sessionConfig{store: fail, cookieName: "sid"}
	sess := &session.Session{ID: "x"}
	ctx = context.WithValue(req.Context(), ctxKeySessionConfig, cfg)
	ctx = context.WithValue(ctx, ctxKeySession, sess)
	if err := DeleteSession(rec, req.WithContext(ctx)); err == nil {
		t.Fatal("存储删除失败应返回错误")
	}
}

// TestSessionCookieExpiryAbsoluteEarlier 覆盖 Cookie 受绝对期限截断。
func TestSessionCookieExpiryAbsoluteEarlier(t *testing.T) {
	now := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	cfg := &sessionConfig{
		lifetime: session.Lifetime{IdleTTL: time.Hour, AbsoluteTTL: 30 * time.Minute},
		now:      func() time.Time { return now },
	}
	got := sessionCookieExpiry(session.Session{AbsoluteExpiresAt: now.Add(20 * time.Minute)}, cfg)
	testx.RequireEqual(t, got, now.Add(20*time.Minute))
}

// TestRotateSessionCSRFErrors 覆盖 CSRF 令牌生成失败时不轮换会话。
func TestRotateSessionCSRFErrors(t *testing.T) {
	store := session.NewMemoryStore(nil)
	sess, err := store.Create(context.Background(), time.Hour)
	testx.RequireNoError(t, err)
	cfg := &sessionConfig{
		store:      store,
		cookieName: "sid",
		lifetime:   session.Lifetime{IdleTTL: time.Hour},
		now:        time.Now,
	}
	csrfCfg := &sessionCSRFConfig{cookieName: "csrf", options: newCSRFOptions()}
	ctx := context.WithValue(context.Background(), ctxKeySessionConfig, cfg)
	ctx = context.WithValue(ctx, ctxKeySession, &sess)
	ctx = context.WithValue(ctx, ctxKeyCSRFConfig, csrfCfg)
	req := httptest.NewRequest(http.MethodGet, "/rotate", nil).WithContext(ctx)

	orig := csrfRand
	csrfRand = func(int) (string, error) { return "", errors.New("随机源失败") }
	defer func() { csrfRand = orig }()
	if err := RotateSession(httptest.NewRecorder(), req); err == nil ||
		!errx.Is(err, authx.CodeCSRFGenerationFailed) {
		t.Fatalf("应返回 CSRF 生成错误：%v", err)
	}
	if got, err := store.Get(context.Background(), sess.ID); err != nil || got.ID != sess.ID {
		t.Fatalf("生成失败不应轮换会话：%+v err=%v", got, err)
	}
}

// TestRotateSessionInitializesCSRFValues 覆盖自定义存储返回空 Values。
func TestRotateSessionInitializesCSRFValues(t *testing.T) {
	cfg := &sessionConfig{
		store:      &nilRotateStore{},
		cookieName: "sid",
		lifetime:   session.Lifetime{IdleTTL: time.Hour},
		now:        time.Now,
	}
	csrfCfg := &sessionCSRFConfig{cookieName: "csrf", options: newCSRFOptions()}
	sess := &session.Session{ID: "old"}
	ctx := context.WithValue(context.Background(), ctxKeySessionConfig, cfg)
	ctx = context.WithValue(ctx, ctxKeySession, sess)
	ctx = context.WithValue(ctx, ctxKeyCSRFConfig, csrfCfg)
	req := httptest.NewRequest(http.MethodGet, "/rotate", nil).WithContext(ctx)
	testx.RequireNoError(t, RotateSession(httptest.NewRecorder(), req))
	testx.RequireEqual(t, sess.ID, "rotated")
	testx.RequireNotEqual(t, sess.Values[sessionCSRFTokenKey], "")
}

func cookieByName(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

type deleteFailStore struct {
	failStore
}

func (s *deleteFailStore) Delete(context.Context, string) error {
	return errors.New("删除失败")
}

type nilRotateStore struct{}

func (s *nilRotateStore) Create(context.Context, time.Duration) (session.Session, error) {
	return session.Session{}, nil
}

func (s *nilRotateStore) Get(context.Context, string) (session.Session, error) {
	return session.Session{}, authx.ErrSessionNotFound
}

func (s *nilRotateStore) Save(context.Context, session.Session, time.Duration) error {
	return nil
}

func (s *nilRotateStore) Delete(context.Context, string) error {
	return nil
}

func (s *nilRotateStore) Rotate(context.Context, string, time.Duration) (session.Session, error) {
	return session.Session{ID: "rotated"}, nil
}
