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
	"github.com/lcylpzls/authx/token"
)

// newSigner 构造测试签发器。
func newSigner(t *testing.T) *token.Signer {
	t.Helper()
	s, err := token.NewHS256([]byte("0123456789abcdef0123456789abcdef"))
	testx.RequireNoError(t, err)
	return s
}

// runChain 在内存中执行标准中间件链，返回响应记录器与请求。
func runChain(t *testing.T, method string, middlewares ...func(http.Handler) http.Handler) (*httptest.ResponseRecorder, *http.Request) {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, "/ping", nil)
	var h http.Handler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	h.ServeHTTP(w, req)
	return w, req
}

// TestAuthPanic 覆盖 nil 签发器。
func TestAuthPanic(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("nil 签发器应 panic")
		}
	}()
	_ = Auth(nil)
}

// TestAuthNoToken 覆盖缺失/畸形令牌。
func TestAuthNoToken(t *testing.T) {
	signer := newSigner(t)
	mw := Auth(signer)
	for _, h := range []string{"", "Basic abc", "Bearer ", "Bearer " + strings.Repeat("x", maxBearerLength+1)} {
		req := httptest.NewRequest(http.MethodGet, "/ping", nil)
		if h != "" {
			req.Header.Set("Authorization", h)
		}
		rec := httptest.NewRecorder()
		mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, req)
		testx.RequireEqual(t, rec.Code, http.StatusUnauthorized)
		testx.RequireEqual(t, rec.Header().Get("WWW-Authenticate"), `Bearer realm=api`)
	}
}

// TestAuthInvalidToken 覆盖签名错误/过期令牌。
func TestAuthInvalidToken(t *testing.T) {
	signer := newSigner(t)
	mw := Auth(signer)
	badSigner, err := token.NewHS256([]byte("other-secret-0123456789abcdefghijkl"))
	testx.RequireNoError(t, err)
	bad, err := badSigner.Sign("u1", token.WithTokenTTL(time.Hour))
	testx.RequireNoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req.Header.Set("Authorization", "Bearer "+bad)
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, req)
	testx.RequireEqual(t, rec.Code, http.StatusUnauthorized)
}

// TestAuthSuccess 覆盖认证成功注入身份。
func TestAuthSuccess(t *testing.T) {
	signer := newSigner(t)
	mw := Auth(signer)
	tok, err := signer.Sign("u1")
	testx.RequireNoError(t, err)

	var gotClaims token.Claims
	var gotUID string
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClaims, _ = ClaimsFrom(r.Context())
		gotUID = UserID(r.Context())
	})).ServeHTTP(rec, req)
	testx.RequireEqual(t, rec.Code, http.StatusOK)
	testx.RequireEqual(t, gotUID, "u1")
	testx.RequireEqual(t, gotClaims.Subject, "u1")
}

// TestRequirePermission 覆盖权限校验分支。
func TestRequirePermission(t *testing.T) {
	signer := newSigner(t)
	r := rbac.New()
	testx.RequireNoError(t, r.AddRole("admin", "orders.read"))
	perm := RequirePermission(r, "orders.read")
	adminTok, _ := signer.Sign("u1", token.WithRoles("admin"))
	userTok, _ := signer.Sign("u2", token.WithRoles("user"))

	mw := Auth(signer)

	// 有权限 → 放行。
	rec := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req2.Header.Set("Authorization", "Bearer "+adminTok)
	mw(perm(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))).ServeHTTP(rec, req2)
	testx.RequireEqual(t, rec.Code, http.StatusNoContent)

	// 无权限 → 403。
	rec3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req3.Header.Set("Authorization", "Bearer "+userTok)
	mw(perm(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))).ServeHTTP(rec3, req3)
	testx.RequireEqual(t, rec3.Code, http.StatusForbidden)

	// 未认证 → 401。
	rec4 := httptest.NewRecorder()
	mw(perm(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))).ServeHTTP(rec4, httptest.NewRequest(http.MethodGet, "/ping", nil))
	testx.RequireEqual(t, rec4.Code, http.StatusUnauthorized)
}

// TestRequirePermissionPanics 覆盖非法参数。
func TestRequirePermissionPanics(t *testing.T) {
	for _, fn := range []func(){
		func() { _ = RequirePermission(nil, "x") },
		func() { _ = RequirePermission(rbac.New(), "") },
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
}

// TestRequireRole 覆盖角色校验分支。
func TestRequireRole(t *testing.T) {
	signer := newSigner(t)
	r := rbac.New()
	roleMW := RequireRole(r, "admin")
	mw := Auth(signer)
	adminTok, _ := signer.Sign("u1", token.WithRoles("admin"))
	userTok, _ := signer.Sign("u2", token.WithRoles("user"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req.Header.Set("Authorization", "Bearer "+adminTok)
	mw(roleMW(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))).ServeHTTP(rec, req)
	testx.RequireEqual(t, rec.Code, http.StatusNoContent)

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req2.Header.Set("Authorization", "Bearer "+userTok)
	mw(roleMW(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))).ServeHTTP(rec2, req2)
	testx.RequireEqual(t, rec2.Code, http.StatusForbidden)
}

// TestCSRF 覆盖双提交校验分支。
func TestCSRF(t *testing.T) {
	mw := CSRF("csrf", "X-CSRF")
	rec, req := runChain(t, http.MethodGet, mw)
	testx.RequireEqual(t, rec.Code, http.StatusOK)
	_ = req

	// 非安全方法令牌不匹配 → 403。
	tok, err := GenerateCSRFToken()
	testx.RequireNoError(t, err)
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/ping", nil)
	req2.AddCookie(&http.Cookie{Name: "csrf", Value: tok})
	req2.Header.Set("X-CSRF", "wrong")
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rec2, req2)
	testx.RequireEqual(t, rec2.Code, http.StatusForbidden)

	// 匹配 → 放行。
	rec3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodPost, "/ping", nil)
	req3.AddCookie(&http.Cookie{Name: "csrf", Value: tok})
	req3.Header.Set("X-CSRF", tok)
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rec3, req3)
	testx.RequireEqual(t, rec3.Code, http.StatusNoContent)
}

// TestCSRFPanics 覆盖非法参数。
func TestCSRFPanics(t *testing.T) {
	for _, fn := range []func(){
		func() { _ = CSRF("", "X") },
		func() { _ = CSRF("c", "") },
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
}

// TestCSRFProtect 覆盖种令牌与校验分支。
func TestCSRFProtect(t *testing.T) {
	mw := CSRFProtect("csrf", "X-CSRF", WithCSRFSecure(false))
	// 首次访问种令牌。
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ping", nil))
	testx.RequireEqual(t, rec.Code, http.StatusNoContent)
	setCookies := rec.Result().Cookies()
	if len(setCookies) == 0 || setCookies[0].Name != "csrf" {
		t.Fatal("应种 CSRF Cookie")
	}
	tok := setCookies[0].Value

	// 匹配令牌放行。
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/ping", nil)
	req2.AddCookie(&http.Cookie{Name: "csrf", Value: tok})
	req2.Header.Set("X-CSRF", tok)
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rec2, req2)
	testx.RequireEqual(t, rec2.Code, http.StatusNoContent)

	// 不匹配 → 403。
	rec3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodPost, "/ping", nil)
	req3.AddCookie(&http.Cookie{Name: "csrf", Value: tok})
	req3.Header.Set("X-CSRF", "wrong")
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rec3, req3)
	testx.RequireEqual(t, rec3.Code, http.StatusForbidden)
}

// TestCSRFProtectPanics 覆盖非法参数。
func TestCSRFProtectPanics(t *testing.T) {
	for _, fn := range []func(){
		func() { _ = CSRFProtect("", "X") },
		func() { _ = CSRFProtect("c", "") },
		func() { _ = CSRFProtect("c", "X", WithCSRFTTL(0)) },
		func() { _ = CSRFProtect("c", "X", WithCSRFErrorHandler(nil)) },
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
}

// TestCSRFOrigin 覆盖 Origin/Referer 校验。
func TestCSRFOrigin(t *testing.T) {
	mw := CSRFProtect("csrf", "X-CSRF", WithCSRFSecure(false), WithCSRFAllowedOrigins("https://app.example.com"))
	tok, _ := GenerateCSRFToken()

	// Origin 不匹配 → 403。
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ping", nil)
	req.AddCookie(&http.Cookie{Name: "csrf", Value: tok})
	req.Header.Set("X-CSRF", tok)
	req.Header.Set("Origin", "https://evil.example.com")
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rec, req)
	testx.RequireEqual(t, rec.Code, http.StatusForbidden)

	// Origin 匹配 → 放行。
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/ping", nil)
	req2.AddCookie(&http.Cookie{Name: "csrf", Value: tok})
	req2.Header.Set("X-CSRF", tok)
	req2.Header.Set("Origin", "https://app.example.com")
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rec2, req2)
	testx.RequireEqual(t, rec2.Code, http.StatusNoContent)
}

// TestGenerateValidateCSRFToken 覆盖令牌生成与校验。
func TestGenerateValidateCSRFToken(t *testing.T) {
	tok, err := GenerateCSRFToken()
	testx.RequireNoError(t, err)
	testx.RequireTrue(t, ValidateCSRFToken(tok, tok))
	testx.RequireFalse(t, ValidateCSRFToken(tok, "x"))
	testx.RequireFalse(t, ValidateCSRFToken("", tok))
	testx.RequireFalse(t, ValidateCSRFToken(strings.Repeat("a", maxCSRFTokenLength+1), tok))
}

// TestDefaultErrorHandler 覆盖默认错误响应。
func TestDefaultErrorHandler(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	DefaultErrorHandler(rec, req, http.StatusForbidden, authx.ErrForbidden)
	testx.RequireEqual(t, rec.Code, http.StatusForbidden)
	testx.RequireTrue(t, strings.Contains(rec.Body.String(), "authx_forbidden"))
}

// TestErrorResponseFrom 覆盖错误语义提取。
func TestErrorResponseFrom(t *testing.T) {
	resp := errorResponseFrom(authx.ErrForbidden)
	testx.RequireEqual(t, resp.Code, string(authx.CodeForbidden))
	resp2 := errorResponseFrom(errors.New("普通错误"))
	testx.RequireEqual(t, resp2.Code, "")
	testx.RequireEqual(t, resp2.Message, "普通错误")
}

// TestBearerToken 覆盖令牌头解析。
func TestBearerToken(t *testing.T) {
	_, ok := bearerToken("")
	testx.RequireFalse(t, ok)
	_, ok = bearerToken("Basic x")
	testx.RequireFalse(t, ok)
	_, ok = bearerToken("Bearer abc")
	testx.RequireTrue(t, ok)
}

// TestClaimsUserIDMissing 覆盖未认证上下文读取。
func TestClaimsUserIDMissing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	if _, ok := ClaimsFrom(req.Context()); ok {
		t.Fatal("未认证不应有 Claims")
	}
	if got := UserID(req.Context()); got != "" {
		t.Fatalf("未认证 UserID 应为空：%s", got)
	}
}

// TestAuthOptions 覆盖认证配置项。
func TestAuthOptions(t *testing.T) {
	opt := WithRealm("admin")
	o := &authOptions{}
	opt(o)
	testx.RequireEqual(t, o.realm, "admin")
	opt2 := WithAuthErrorHandler(DefaultErrorHandler)
	o2 := &authOptions{}
	opt2(o2)
	testx.RequireNotNil(t, o2.errorHandler)
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("nil 错误处理器应 panic")
			}
		}()
		WithAuthErrorHandler(nil)(&authOptions{})
	}()
}

// TestCSRFOptions 覆盖 CSRF 配置项。
func TestCSRFOptions(t *testing.T) {
	o := &csrfOptions{}
	WithCSRFSecure(false)(o)
	WithCSRFHTTPOnly(true)(o)
	WithCSRFPath("/x")(o)
	WithCSRFSameSite(http.SameSiteStrictMode)(o)
	WithCSRFTTL(time.Hour)(o)
	WithCSRFClock(time.Now)(o)
	WithCSRFErrorHandler(DefaultErrorHandler)(o)
	WithCSRFAllowedOrigins("https://a.com/")(o)
	testx.RequireEqual(t, o.origins[0], "https://a.com")
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("nil CSRF 错误处理器应 panic")
			}
		}()
		WithCSRFErrorHandler(nil)(&csrfOptions{})
	}()
}

// TestSessionCSRFBinding 覆盖会话绑定、跨会话拒绝和来源校验。
func TestSessionCSRFBinding(t *testing.T) {
	store := session.NewMemoryStore(nil)
	sessionMW := Session(store, "sid", WithSessionSecure(false))
	csrfMW := SessionCSRFProtect("csrf", "X-CSRF",
		WithCSRFSecure(false),
		WithCSRFAllowedOrigins("https://app.example.com"))
	chain := sessionMW(csrfMW(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))

	seed := httptest.NewRecorder()
	chain.ServeHTTP(seed, httptest.NewRequest(http.MethodGet, "/seed", nil))
	testx.RequireEqual(t, seed.Code, http.StatusNoContent)
	sid := cookieByName(seed.Result().Cookies(), "sid")
	csrf := cookieByName(seed.Result().Cookies(), "csrf")
	testx.RequireNotNil(t, sid)
	testx.RequireNotNil(t, csrf)

	post := func(sessionCookie, csrfCookie *http.Cookie, header, origin string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/change", nil)
		req.AddCookie(sessionCookie)
		req.AddCookie(csrfCookie)
		req.Header.Set("X-CSRF", header)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		chain.ServeHTTP(rec, req)
		return rec.Code
	}

	testx.RequireEqual(t, post(sid, csrf, csrf.Value, "https://app.example.com"),
		http.StatusNoContent)
	testx.RequireEqual(t, post(sid, csrf, "wrong", "https://app.example.com"),
		http.StatusForbidden)
	testx.RequireEqual(t, post(sid, csrf, csrf.Value, "https://evil.example.com"),
		http.StatusForbidden)

	second := httptest.NewRecorder()
	sessionMW(csrfMW(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))).ServeHTTP(
		second, httptest.NewRequest(http.MethodGet, "/seed", nil))
	foreign := cookieByName(second.Result().Cookies(), "csrf")
	testx.RequireNotNil(t, foreign)
	testx.RequireEqual(t, post(sid, foreign, foreign.Value, "https://app.example.com"),
		http.StatusForbidden)
}

// TestSessionCSRFRotation 覆盖会话轮换时同步更换 CSRF 令牌。
func TestSessionCSRFRotation(t *testing.T) {
	store := session.NewMemoryStore(nil)
	sessionMW := Session(store, "sid", WithSessionSecure(false))
	csrfMW := SessionCSRFProtect("csrf", "X-CSRF", WithCSRFSecure(false))
	var oldSID, oldToken string
	var rotatedSID, rotatedToken string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, _ := SessionFrom(r.Context())
		oldSID = sess.ID
		oldToken = sess.Values[sessionCSRFTokenKey]
		testx.RequireNoError(t, RotateSession(w, r))
		rotated, _ := SessionFrom(r.Context())
		rotatedSID = rotated.ID
		rotatedToken = rotated.Values[sessionCSRFTokenKey]
		w.WriteHeader(http.StatusNoContent)
	})
	chain := sessionMW(csrfMW(handler))
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/rotate", nil))
	testx.RequireNotEqual(t, oldSID, rotatedSID)
	testx.RequireNotEqual(t, oldToken, rotatedToken)
	csrfCookie := lastCookieByName(rec.Result().Cookies(), "csrf")
	testx.RequireNotNil(t, csrfCookie)
	testx.RequireEqual(t, csrfCookie.Value, rotatedToken)
}

// TestSessionCSRFErrors 覆盖缺少会话、令牌生成失败与 Cookie 缺失。
func TestSessionCSRFErrors(t *testing.T) {
	for _, fn := range []func(){
		func() { _ = SessionCSRFProtect("", "X") },
		func() { _ = SessionCSRFProtect("c", "") },
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

	csrfMW := SessionCSRFProtect("csrf", "X-CSRF", WithCSRFSecure(false))
	rec := httptest.NewRecorder()
	csrfMW(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(
		rec, httptest.NewRequest(http.MethodGet, "/missing-session", nil))
	testx.RequireEqual(t, rec.Code, http.StatusInternalServerError)

	orig := csrfRand
	csrfRand = func(int) (string, error) { return "", errors.New("随机源失败") }
	defer func() { csrfRand = orig }()
	store := session.NewMemoryStore(nil)
	chain := Session(store, "sid", WithSessionSecure(false))(
		csrfMW(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
	rec2 := httptest.NewRecorder()
	chain.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/seed", nil))
	testx.RequireEqual(t, rec2.Code, http.StatusInternalServerError)
}

// TestSessionCSRFMissingCookieAndNilValues 覆盖无 Cookie 拒绝与空值建表。
func TestSessionCSRFMissingCookieAndNilValues(t *testing.T) {
	cfg := &sessionConfig{
		store:      session.NewMemoryStore(nil),
		cookieName: "sid",
		lifetime:   session.Lifetime{IdleTTL: time.Hour},
		now:        time.Now,
	}
	sess := &session.Session{ID: "s-1"}
	ctx := context.WithValue(context.Background(), ctxKeySessionConfig, cfg)
	ctx = context.WithValue(ctx, ctxKeySession, sess)
	mw := SessionCSRFProtect("csrf", "X-CSRF", WithCSRFSecure(false))
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(
		rec, httptest.NewRequest(http.MethodGet, "/seed", nil).WithContext(ctx))
	testx.RequireNotNil(t, cookieByName(rec.Result().Cookies(), "csrf"))
	testx.RequireNotEqual(t, sess.Values[sessionCSRFTokenKey], "")

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/change", nil)
	req2 = req2.WithContext(ctx)
	req2.Header.Set("X-CSRF", sess.Values[sessionCSRFTokenKey])
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec2, req2)
	testx.RequireEqual(t, rec2.Code, http.StatusForbidden)
}

// TestDeleteSessionCSRFCookie 覆盖登出时同时失效 CSRF Cookie。
func TestDeleteSessionCSRFCookie(t *testing.T) {
	store := session.NewMemoryStore(nil)
	sessionMW := Session(store, "sid", WithSessionSecure(false))
	csrfMW := SessionCSRFProtect("csrf", "X-CSRF", WithCSRFSecure(false))
	chain := sessionMW(csrfMW(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testx.RequireNoError(t, DeleteSession(w, r))
	})))
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/logout", nil))
	csrfCookie := lastCookieByName(rec.Result().Cookies(), "csrf")
	testx.RequireNotNil(t, csrfCookie)
	testx.RequireEqual(t, csrfCookie.MaxAge, -1)
}

func lastCookieByName(cookies []*http.Cookie, name string) *http.Cookie {
	var result *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == name {
			result = cookie
		}
	}
	return result
}
