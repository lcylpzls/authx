package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	testx "github.com/lcylpzls/testx"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/authx/rbac"
	"github.com/lcylpzls/authx/session"
)

// errStore 是可控错误的会话存储。
type errStore struct {
	createErr error
	getErr    error
	rotateErr error
}

func (s *errStore) Create(context.Context, time.Duration) (session.Session, error) {
	if s.createErr != nil {
		return session.Session{}, s.createErr
	}
	return session.Session{ID: "new", Values: map[string]string{}}, nil
}

func (s *errStore) Get(_ context.Context, id string) (session.Session, error) {
	if s.getErr != nil {
		return session.Session{}, s.getErr
	}
	return session.Session{ID: id, Values: map[string]string{}}, nil
}

func (s *errStore) Save(context.Context, session.Session, time.Duration) error { return nil }
func (s *errStore) Delete(context.Context, string) error                       { return nil }
func (s *errStore) Rotate(context.Context, string, time.Duration) (session.Session, error) {
	if s.rotateErr != nil {
		return session.Session{}, s.rotateErr
	}
	return session.Session{ID: "rotated", Values: map[string]string{}}, nil
}

// TestAuthWithOptions 覆盖认证中间件选项循环与自定义 realm。
func TestAuthWithOptions(t *testing.T) {
	signer := newSigner(t)
	tok, err := signer.Sign("u1")
	testx.RequireNoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	Auth(signer, WithRealm("admin"))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rec, req)
	testx.RequireEqual(t, rec.Code, http.StatusNoContent)

	rec2 := httptest.NewRecorder()
	Auth(signer, WithRealm("admin"))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/ping", nil))
	testx.RequireEqual(t, rec2.Code, http.StatusUnauthorized)
	testx.RequireEqual(t, rec2.Header().Get("WWW-Authenticate"), `Bearer realm=admin`)
}

// TestRequirePermissionNoClaims 覆盖未认证上下文时的 401。
func TestRequirePermissionNoClaims(t *testing.T) {
	rec, _ := runChain(t, http.MethodGet, RequirePermission(rbac.New(), "orders.read"))
	testx.RequireEqual(t, rec.Code, http.StatusUnauthorized)
}

// TestRequireRolePanicsAndNoClaims 覆盖角色中间件的 panic 与未认证分支。
func TestRequireRolePanicsAndNoClaims(t *testing.T) {
	for _, fn := range []func(){
		func() { _ = RequireRole(nil, "admin") },
		func() { _ = RequireRole(rbac.New(), "") },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatal("非法参数应 panic")
				}
			}()
			fn()
		}()
	}
	rec, _ := runChain(t, http.MethodGet, RequireRole(rbac.New(), "admin"))
	testx.RequireEqual(t, rec.Code, http.StatusUnauthorized)
}

// TestCSRFSkipMethods 覆盖 CSRF 跳过方法扩展。
func TestCSRFSkipMethods(t *testing.T) {
	hit := false
	mw := CSRF("csrf", "X-CSRF", "post")
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/ping", nil))
	testx.RequireTrue(t, hit)
	testx.RequireEqual(t, rec.Code, http.StatusNoContent)
}

// TestGenerateCSRFTokenError 覆盖令牌生成失败分支。
func TestGenerateCSRFTokenError(t *testing.T) {
	orig := csrfRand
	defer func() { csrfRand = orig }()
	csrfRand = func(int) (string, error) { return "", errors.New("随机源失败") }

	if _, err := GenerateCSRFToken(); err == nil {
		t.Fatal("随机源失败应报错")
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ping", nil)
	CSRFProtect("csrf", "X-CSRF", WithCSRFSecure(false))(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}),
	).ServeHTTP(rec, req)
	testx.RequireEqual(t, rec.Code, http.StatusInternalServerError)
}

// TestCSRFNilClock 覆盖 CSRF 中间件时间源为空时的默认分支。
func TestCSRFNilClock(t *testing.T) {
	rec := httptest.NewRecorder()
	CSRFProtect("csrf", "X-CSRF", WithCSRFClock(nil), WithCSRFSecure(false))(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}),
	).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ping", nil))
	testx.RequireEqual(t, rec.Code, http.StatusNoContent)
}

// TestCSRFRefererBranches 覆盖 Referer 回退校验的多个分支。
func TestCSRFRefererBranches(t *testing.T) {
	mw := CSRFProtect("csrf", "X-CSRF", WithCSRFSecure(false),
		WithCSRFAllowedOrigins("https://app.example.com"))
	tok, err := GenerateCSRFToken()
	testx.RequireNoError(t, err)

	run := func(mutate func(*http.Request)) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/ping", nil)
		req.AddCookie(&http.Cookie{Name: "csrf", Value: tok})
		req.Header.Set("X-CSRF", tok)
		mutate(req)
		mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})).ServeHTTP(rec, req)
		return rec.Code
	}

	testx.RequireEqual(t, run(func(r *http.Request) {
		r.Header.Set("Origin", strings.Repeat("a", maxOriginLength+1))
	}), http.StatusForbidden)
	testx.RequireEqual(t, run(func(r *http.Request) {
		r.Header.Set("Referer", strings.Repeat("a", maxOriginLength+1))
	}), http.StatusForbidden)
	testx.RequireEqual(t, run(func(r *http.Request) {
		r.Header.Set("Referer", "://bad")
	}), http.StatusForbidden)
	testx.RequireEqual(t, run(func(r *http.Request) {
		r.Header.Set("Referer", "https://app.example.com/x")
	}), http.StatusNoContent)
	testx.RequireEqual(t, run(func(r *http.Request) {}), http.StatusForbidden)
}

// TestSessionNilClock 覆盖会话时间源为空时的默认分支。
func TestSessionNilClock(t *testing.T) {
	store := session.NewMemoryStore(nil)
	rec := httptest.NewRecorder()
	Session(store, "sid", WithSessionClock(nil), WithSessionSecure(false))(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}),
	).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ping", nil))
	testx.RequireEqual(t, rec.Code, http.StatusNoContent)
}

// TestSessionLoadError 覆盖会话读取失败返回 500。
func TestSessionLoadError(t *testing.T) {
	mw := Session(&errStore{getErr: errors.New("读取失败")}, "sid", WithSessionSecure(false))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: "abc"})
	mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rec, req)
	testx.RequireEqual(t, rec.Code, http.StatusInternalServerError)
}

// TestSessionCreateError 覆盖会话创建失败返回 500。
func TestSessionCreateError(t *testing.T) {
	mw := Session(&errStore{createErr: errors.New("创建失败")}, "sid", WithSessionSecure(false))
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ping", nil))
	testx.RequireEqual(t, rec.Code, http.StatusInternalServerError)
}

// TestSessionSigningKeyPaths 覆盖签名 Cookie 的校验路径。
func TestSessionSigningKeyPaths(t *testing.T) {
	key := make([]byte, 32)
	mw := Session(&errStore{}, "sid", WithSessionSecure(false), WithSessionSigningKey(key))

	// 签名无效 → 视为无会话。
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: "abc.invalid"})
	mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rec, req)
	testx.RequireEqual(t, rec.Code, http.StatusNoContent)

	// 签名有效 → 读取既有会话。
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req2.AddCookie(&http.Cookie{Name: "sid", Value: signedSessionValue("real", key)})
	var gotID string
	mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		s, _ := SessionFrom(r.Context())
		gotID = s.ID
	})).ServeHTTP(rec2, req2)
	testx.RequireEqual(t, gotID, "real")

	// 会话不存在 → 新建。
	mwNotFound := Session(&errStore{getErr: authx.ErrSessionNotFound}, "sid",
		WithSessionSecure(false), WithSessionSigningKey(key))
	rec3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req3.AddCookie(&http.Cookie{Name: "sid", Value: signedSessionValue("missing", key)})
	mwNotFound(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rec3, req3)
	testx.RequireEqual(t, rec3.Code, http.StatusNoContent)
}

// TestSignedSessionValue 覆盖带签名会话值构造。
func TestSignedSessionValue(t *testing.T) {
	got := signedSessionValue("id", make([]byte, 32))
	if !strings.HasPrefix(got, "id.") {
		t.Fatalf("签名值格式不符：%s", got)
	}
}

// TestVerifySessionCookie 覆盖签名校验分支。
func TestVerifySessionCookie(t *testing.T) {
	key := make([]byte, 32)
	for _, v := range []string{"nodot", ".abc", "abc."} {
		if _, ok := verifySessionCookie(v, key); ok {
			t.Fatalf("非法格式应拒绝：%s", v)
		}
	}
	signed := signedSessionValue("abc", key)
	id, ok := verifySessionCookie(signed, key)
	if !ok || id != "abc" {
		t.Fatalf("合法签名应通过：%q %v", id, ok)
	}
	if _, ok := verifySessionCookie(signed[:len(signed)-1]+"x", key); ok {
		t.Fatal("篡改签名应拒绝")
	}
}

// TestRotateSessionEdgeCases 覆盖轮换会话的异常分支。
func TestRotateSessionEdgeCases(t *testing.T) {
	ctx := context.Background()
	cfg := &sessionConfig{store: session.NewMemoryStore(nil), cookieName: "sid",
		ttl: time.Hour, secure: false, now: time.Now}

	req1 := httptest.NewRequest(http.MethodGet, "/ping", nil).WithContext(
		context.WithValue(ctx, ctxKeySessionConfig, "not-config"))
	if err := RotateSession(httptest.NewRecorder(), req1); !errors.Is(err, authx.ErrSessionInvalid) {
		t.Fatalf("配置类型错误应返回 ErrSessionInvalid：%v", err)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/ping", nil).WithContext(
		context.WithValue(ctx, ctxKeySessionConfig, cfg))
	if err := RotateSession(httptest.NewRecorder(), req2); !errors.Is(err, authx.ErrSessionNotFound) {
		t.Fatalf("无会话应返回 ErrSessionNotFound：%v", err)
	}

	req3 := httptest.NewRequest(http.MethodGet, "/ping", nil).WithContext(
		context.WithValue(context.WithValue(ctx, ctxKeySessionConfig, cfg),
			ctxKeySession, session.Session{ID: "x", Values: map[string]string{}}))
	if err := RotateSession(httptest.NewRecorder(), req3); !errors.Is(err, authx.ErrSessionNotFound) {
		t.Fatalf("会话值类型错误应返回 ErrSessionNotFound：%v", err)
	}

	req4 := httptest.NewRequest(http.MethodGet, "/ping", nil).WithContext(
		context.WithValue(context.WithValue(ctx, ctxKeySessionConfig, cfg),
			ctxKeySession, &session.Session{ID: "x", Values: map[string]string{}}))
	cfg.store = &errStore{rotateErr: errors.New("轮换失败")}
	if err := RotateSession(httptest.NewRecorder(), req4); err == nil {
		t.Fatal("轮换失败应返回错误")
	}
}

// TestSessionFromBadValue 覆盖上下文中会话值类型错误。
func TestSessionFromBadValue(t *testing.T) {
	ctx := context.WithValue(context.Background(), ctxKeySession, "x")
	if _, ok := SessionFrom(ctx); ok {
		t.Fatal("类型错误应返回 false")
	}
}
