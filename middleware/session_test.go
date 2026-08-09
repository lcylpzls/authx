package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/authx/session"
	"github.com/lcylpzls/logx"
	"github.com/lcylpzls/webx"
)

// TestSessionPanics 覆盖会话中间件 panic 分支。
func TestSessionPanics(t *testing.T) {
	store := session.NewMemoryStore(nil)
	for name, fn := range map[string]func(){
		"空存储":        func() { _ = Session(nil, "sid") },
		"空 Cookie 名": func() { _ = Session(store, "") },
		"零 TTL":      func() { _ = Session(store, "sid", WithSessionTTL(0)) },
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

// TestSessionFlow 覆盖会话中间件主流程。
func TestSessionFlow(t *testing.T) {
	store := session.NewMemoryStore(nil)
	mw := Session(store, "sid", WithSessionTTL(time.Hour), WithSessionSecure(false))
	handled := false
	var sid string
	// 无 Cookie → 新建并种 Cookie。
	w, _ := runChain(t, http.MethodGet, mw, func(c *webx.Context) {
		handled = true
		s, ok := SessionFrom(c)
		if !ok || s.ID == "" {
			t.Fatal("会话应注入上下文")
		}
		sid = s.ID
	})
	if w.Code != http.StatusOK || !handled {
		t.Fatalf("新会话应放行：code=%d handled=%v", w.Code, handled)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "sid" || cookies[0].Value != sid {
		t.Fatalf("应种会话 Cookie：%+v", cookies)
	}
	// 已有 Cookie → 复用会话。
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: sid})
	w2 := httptest.NewRecorder()
	c2 := webx.NewContext(w2, req)
	handled = false
	c2.SetHandlers([]webx.HandlerFunc{mw, func(c *webx.Context) {
		handled = true
		s, _ := SessionFrom(c)
		if s.ID != sid {
			t.Fatalf("应复用已有会话：%q", s.ID)
		}
		s.Values["k"] = "v"
	}})
	c2.Run()
	if !handled {
		t.Fatal("已有会话应放行")
	}
	// 请求结束后自动保存（验证 Values 落库）。
	got, err := store.Get(context.Background(), sid)
	if err != nil || got.Values["k"] != "v" {
		t.Fatalf("会话应自动保存：%+v err=%v", got, err)
	}
}

// TestSessionOptions 覆盖会话中间件全部配置项。
func TestSessionOptions(t *testing.T) {
	store := session.NewMemoryStore(nil)
	mw := Session(store, "sid",
		WithSessionSecure(true),
		WithSessionHTTPOnly(false),
		WithSessionPath("/app"),
		WithSessionSameSite(http.SameSiteStrictMode),
	)
	w, _ := runChain(t, http.MethodGet, mw)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || cookies[0].HttpOnly ||
		cookies[0].Path != "/app" || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("Cookie 属性不符：%+v", cookies)
	}
}

// TestSessionFromMissing 覆盖无会话上下文读取。
func TestSessionFromMissing(t *testing.T) {
	_, c := runChain(t, http.MethodGet)
	if _, ok := SessionFrom(c); ok {
		t.Fatal("无会话上下文应返回 false")
	}
}

// TestSessionLoadErrors 覆盖加载与创建失败路径。
func TestSessionLoadErrors(t *testing.T) {
	good := session.NewMemoryStore(nil)
	// 无效 Cookie（会话不存在）→ 新建。
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: "not-exist"})
	w := httptest.NewRecorder()
	c := webx.NewContext(w, req)
	mw := Session(good, "sid", WithSessionSecure(false))
	handled := false
	c.SetHandlers([]webx.HandlerFunc{mw, func(c *webx.Context) { handled = true }})
	c.Run()
	if w.Code != http.StatusOK || !handled {
		t.Fatalf("无效会话应重建：code=%d handled=%v", w.Code, handled)
	}
	// 存储读取错误 → 500。
	fail := failingSessionStore{err: errors.New("存储故障")}
	req2 := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req2.AddCookie(&http.Cookie{Name: "sid", Value: "x"})
	w2 := httptest.NewRecorder()
	c2 := webx.NewContext(w2, req2)
	mw2 := Session(fail, "sid")
	handled = false
	c2.SetHandlers([]webx.HandlerFunc{mw2, func(c *webx.Context) { handled = true }})
	c2.Run()
	if w2.Code != http.StatusInternalServerError || handled {
		t.Fatalf("读取失败应 500：code=%d handled=%v", w2.Code, handled)
	}
	// 创建失败 → 500。
	fail2 := failingSessionStore{createErr: errors.New("创建失败")}
	req3 := httptest.NewRequest(http.MethodGet, "/ping", nil)
	w3 := httptest.NewRecorder()
	c3 := webx.NewContext(w3, req3)
	mw3 := Session(fail2, "sid")
	handled = false
	c3.SetHandlers([]webx.HandlerFunc{mw3, func(c *webx.Context) { handled = true }})
	c3.Run()
	if w3.Code != http.StatusInternalServerError || handled {
		t.Fatalf("创建失败应 500：code=%d handled=%v", w3.Code, handled)
	}
	// SessionFrom 类型不符。
	_, c4 := runChain(t, http.MethodGet)
	c4.Set("authx_session", "not-session")
	if _, ok := SessionFrom(c4); ok {
		t.Fatal("类型不符应返回 false")
	}
}

// failingSessionStore 固定错误的会话存储。
type failingSessionStore struct {
	err       error
	createErr error
	saveErr   error
}

func (f failingSessionStore) Create(context.Context, time.Duration) (session.Session, error) {
	return session.Session{}, f.createErr
}

func (f failingSessionStore) Get(context.Context, string) (session.Session, error) {
	return session.Session{}, f.err
}

func (f failingSessionStore) Save(context.Context, session.Session, time.Duration) error {
	return f.saveErr
}
func (f failingSessionStore) Delete(context.Context, string) error { return nil }
func (f failingSessionStore) Rotate(context.Context, string, time.Duration) (session.Session, error) {
	return session.Session{}, f.err
}

var _ session.Store = failingSessionStore{}

// TestRotateSessionFlow 覆盖登录后会话轮换（防会话固定）。
func TestRotateSessionFlow(t *testing.T) {
	store := session.NewMemoryStore(nil)
	mw := Session(store, "sid", WithSessionSecure(false))
	var sid string
	_, c := runChain(t, http.MethodGet, mw, func(c *webx.Context) {
		s, _ := SessionFrom(c)
		sid = s.ID
		s.Values["k"] = "v"
		if err := RotateSession(c); err != nil {
			t.Fatalf("轮换失败：%v", err)
		}
	})
	_ = c
	// 旧会话已被轮换删除，新会话保留值。
	if _, err := store.Get(context.Background(), sid); err == nil {
		t.Fatal("旧会话应已删除")
	}
	if store.Cleanup() != 0 {
		t.Fatal("轮换后不应残留旧条目")
	}
}

// TestRotateSessionCookie 覆盖轮换后 Cookie 与上下文更新。
func TestRotateSessionCookie(t *testing.T) {
	store := session.NewMemoryStore(nil)
	mw := Session(store, "sid", WithSessionSecure(false))
	var newID string
	var rotated *http.Cookie
	w, _ := runChain(t, http.MethodGet, mw, func(c *webx.Context) {
		s, _ := SessionFrom(c)
		s.Values["k"] = "v"
		if err := RotateSession(c); err != nil {
			t.Fatal(err)
		}
		s2, _ := SessionFrom(c)
		newID = s2.ID
	})
	for _, ck := range w.Result().Cookies() {
		if ck.Name == "sid" {
			rotated = ck
		}
	}
	if rotated == nil || rotated.Value != newID {
		t.Fatalf("Cookie 应更新为新会话 ID：%v new=%q", rotated, newID)
	}
}

// TestRotateSessionErrors 覆盖轮换错误分支。
func TestRotateSessionErrors(t *testing.T) {
	// 未装配会话中间件。
	_, c := runChain(t, http.MethodGet)
	if err := RotateSession(c); !errors.Is(err, authx.ErrSessionInvalid) {
		t.Fatalf("未装配应报会话参数错误，实际：%v", err)
	}
	// 配置类型不符。
	_, c2 := runChain(t, http.MethodGet)
	c2.Set("authx_session_config", "not-config")
	if err := RotateSession(c2); !errors.Is(err, authx.ErrSessionInvalid) {
		t.Fatalf("配置类型不符应报错，实际：%v", err)
	}
	// 无会话。
	_, c3 := runChain(t, http.MethodGet)
	c3.Set("authx_session_config", &sessionConfig{store: session.NewMemoryStore(nil), cookieName: "sid",
		ttl: time.Hour, now: time.Now})
	if err := RotateSession(c3); !errors.Is(err, authx.ErrSessionNotFound) {
		t.Fatalf("无会话应报不存在，实际：%v", err)
	}
	// 存储轮换失败。
	fail := failingSessionStore{err: errors.New("存储故障")}
	_, c4 := runChain(t, http.MethodGet, Session(fail, "sid"))
	c4.Set("authx_session", session.Session{ID: "x"})
	if err := RotateSession(c4); err == nil || !strings.Contains(err.Error(), "存储故障") {
		t.Fatalf("存储失败应透传，实际：%v", err)
	}
}

// recordingLogger 记录 Warn 调用以便断言会话保存失败日志。
type recordingLogger struct {
	warned []string
}

func (r *recordingLogger) IsDebugEnabled() bool                    { return false }
func (r *recordingLogger) Debug(string, logx.FieldGroup)           {}
func (r *recordingLogger) Info(string, logx.FieldGroup)            {}
func (r *recordingLogger) Warn(msg string, _ logx.FieldGroup)      { r.warned = append(r.warned, msg) }
func (r *recordingLogger) Error(string, logx.FieldGroup)           {}
func (r *recordingLogger) Panic(string, logx.FieldGroup)           {}
func (r *recordingLogger) Fatal(string, logx.FieldGroup)           {}
func (r *recordingLogger) Debugf(string, ...any)                   {}
func (r *recordingLogger) Infof(string, ...any)                    {}
func (r *recordingLogger) Warnf(string, ...any)                    {}
func (r *recordingLogger) Errorf(string, ...any)                   {}
func (r *recordingLogger) Panicf(string, ...any)                   {}
func (r *recordingLogger) Fatalf(string, ...any)                   {}
func (r *recordingLogger) WithContext(context.Context) logx.Logger { return r }
func (r *recordingLogger) WithField(string, any) logx.Logger       { return r }
func (r *recordingLogger) Sync() error                             { return nil }
func (r *recordingLogger) Close() error                            { return nil }
func (r *recordingLogger) SafeExit(func())                         {}

// TestSessionSaveErrorLogged 覆盖保存失败时注入日志器记录告警。
func TestSessionSaveErrorLogged(t *testing.T) {
	logger := &recordingLogger{}
	fail := failingSessionStore{createErr: nil, saveErr: errors.New("保存失败")}
	_, _ = runChain(t, http.MethodGet, Session(fail, "sid", WithSessionLogger(logger)))
	if len(logger.warned) != 1 || logger.warned[0] != "会话保存失败" {
		t.Fatalf("应记录一次保存失败告警：%v", logger.warned)
	}
}

// TestSessionClock 覆盖 Cookie 过期时间使用注入时钟。
func TestSessionClock(t *testing.T) {
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	store := session.NewMemoryStore(func() time.Time { return now })
	mw := Session(store, "sid", WithSessionClock(func() time.Time { return now }),
		WithSessionTTL(time.Hour), WithSessionSecure(false))
	w, _ := runChain(t, http.MethodGet, mw)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Expires.Equal(now.Add(time.Hour)) {
		t.Fatalf("Cookie 过期时间应使用注入时钟：%+v", cookies)
	}
	// nil 时钟回退到 time.Now，不应 panic。
	mwNil := Session(store, "sid", WithSessionClock(nil), WithSessionSecure(false))
	w2, _ := runChain(t, http.MethodGet, mwNil)
	if w2.Code != http.StatusOK {
		t.Fatalf("nil 时钟回退应正常放行：%d", w2.Code)
	}
}

// TestSessionErrorHandler 覆盖会话自定义错误处理器。
func TestSessionErrorHandler(t *testing.T) {
	type call struct {
		status int
		err    error
	}
	calls := make([]call, 0, 1)
	handler := func(c *webx.Context, status int, err error) {
		calls = append(calls, call{status: status, err: err})
		c.AbortWithStatusJSON(status, err.Error(), nil)
	}
	fail := failingSessionStore{err: errors.New("存储故障")}
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: "x"})
	w := httptest.NewRecorder()
	c := webx.NewContext(w, req)
	c.SetHandlers([]webx.HandlerFunc{Session(fail, "sid", WithSessionErrorHandler(handler))})
	c.Run()
	if w.Code != http.StatusInternalServerError || len(calls) != 1 ||
		!strings.Contains(calls[0].err.Error(), "存储故障") {
		t.Fatalf("会话失败应调用自定义处理器：code=%d calls=%+v", w.Code, calls)
	}
}

// TestWithSessionErrorHandlerPanic 覆盖 nil 处理器 panic。
func TestWithSessionErrorHandlerPanic(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("nil 处理器应 panic")
		}
	}()
	_ = Session(session.NewMemoryStore(nil), "sid", WithSessionErrorHandler(nil))
}
