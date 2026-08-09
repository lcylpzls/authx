package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lcylpzls/authx/session"
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
}

func (f failingSessionStore) Create(context.Context, time.Duration) (session.Session, error) {
	return session.Session{}, f.createErr
}

func (f failingSessionStore) Get(context.Context, string) (session.Session, error) {
	return session.Session{}, f.err
}

func (f failingSessionStore) Save(context.Context, session.Session, time.Duration) error { return nil }
func (f failingSessionStore) Delete(context.Context, string) error                       { return nil }

var _ session.Store = failingSessionStore{}
