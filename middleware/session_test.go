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
	"github.com/lcylpzls/logx"
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
	WithSessionSecure(false)(o)
	WithSessionHTTPOnly(false)(o)
	WithSessionPath("/x")(o)
	WithSessionSameSite(http.SameSiteStrictMode)(o)
	WithSessionLogger(nil)(o)
	WithSessionClock(time.Now)(o)
	WithSessionErrorHandler(DefaultErrorHandler)(o)
	WithSessionSigningKey(make([]byte, 32))(o)
	testx.RequireEqual(t, o.path, "/x")
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
