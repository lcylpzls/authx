package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lcylpzls/authx/rbac"
	"github.com/lcylpzls/authx/token"
	"github.com/lcylpzls/webx"
)

// newSigner 构造测试签发器。
func newSigner(t *testing.T) *token.Signer {
	t.Helper()
	s, err := token.NewHS256([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// runChain 在内存中执行中间件链。
func runChain(t *testing.T, method string, handlers ...webx.HandlerFunc) (*httptest.ResponseRecorder, *webx.Context) {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, "/ping", nil)
	c := webx.NewContext(w, req)
	c.SetHandlers(handlers)
	c.Run()
	return w, c
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

// TestAuth 覆盖认证成功与失败路径。
func TestAuth(t *testing.T) {
	s := newSigner(t)
	handled := false
	mw := Auth(s, WithRealm("console"))
	// 无 Authorization 头。
	w, _ := runChain(t, http.MethodGet, mw, func(c *webx.Context) { handled = true })
	if w.Code != http.StatusUnauthorized || handled {
		t.Fatalf("无令牌应 401：code=%d handled=%v", w.Code, handled)
	}
	if got := w.Header().Get("WWW-Authenticate"); got != "Bearer realm=console" {
		t.Fatalf("WWW-Authenticate 不符：%q", got)
	}
	// 非法令牌。
	handled = false
	req2 := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req2.Header.Set("Authorization", "Bearer bad.token")
	w2 := httptest.NewRecorder()
	c2 := webx.NewContext(w2, req2)
	c2.SetHandlers([]webx.HandlerFunc{mw, func(c *webx.Context) { handled = true }})
	c2.Run()
	if w2.Code != http.StatusUnauthorized || handled {
		t.Fatalf("非法令牌应 401：code=%d handled=%v", w2.Code, handled)
	}
	// 有效令牌。
	raw, err := s.Sign("u-1001", token.WithRoles("admin"))
	if err != nil {
		t.Fatal(err)
	}
	handled = false
	req3 := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req3.Header.Set("Authorization", "Bearer "+raw)
	w3 := httptest.NewRecorder()
	c3 := webx.NewContext(w3, req3)
	c3.SetHandlers([]webx.HandlerFunc{mw, func(c *webx.Context) { handled = true }})
	c3.Run()
	if !handled || w3.Code != http.StatusOK {
		t.Fatalf("有效令牌应放行：code=%d handled=%v", w3.Code, handled)
	}
	if got := UserID(c3); got != "u-1001" {
		t.Fatalf("UserID 不符：%q", got)
	}
	claims, ok := ClaimsFrom(c3)
	if !ok || claims.Subject != "u-1001" || len(claims.Roles) != 1 {
		t.Fatalf("Claims 不符：ok=%v claims=%+v", ok, claims)
	}
}

// TestClaimsHelpers 覆盖上下文读取失败分支。
func TestClaimsHelpers(t *testing.T) {
	_, c := runChain(t, http.MethodGet)
	if _, ok := ClaimsFrom(c); ok {
		t.Fatal("空上下文不应有 Claims")
	}
	if got := UserID(c); got != "" {
		t.Fatalf("空上下文 UserID 应为空：%q", got)
	}
	_, c2 := runChain(t, http.MethodGet)
	c2.Set("authx_claims", "not-claims")
	if _, ok := ClaimsFrom(c2); ok {
		t.Fatal("类型不符应返回 false")
	}
}

// TestRequirePermission 覆盖权限中间件。
func TestRequirePermission(t *testing.T) {
	rb := rbac.New()
	if err := rb.AddRole("admin", "order:read"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("nil RBAC 应 panic")
		}
	}()
	_ = RequirePermission(nil, "order:read")
}

// TestRequirePermissionFlow 覆盖权限判定流程。
func TestRequirePermissionFlow(t *testing.T) {
	s := newSigner(t)
	rb := rbac.New()
	_ = rb.AddRole("admin", "order:read")
	mw := Auth(s)
	perm := RequirePermission(rb, "order:read")
	handled := false
	// 无认证 → 401。
	w, _ := runChain(t, http.MethodGet, perm, func(c *webx.Context) { handled = true })
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("未认证应 401：%d", w.Code)
	}
	// 有权限 → 放行。
	raw, _ := s.Sign("u-1", token.WithRoles("admin"))
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	w2 := httptest.NewRecorder()
	c2 := webx.NewContext(w2, req)
	handled = false
	c2.SetHandlers([]webx.HandlerFunc{mw, perm, func(c *webx.Context) { handled = true }})
	c2.Run()
	if w2.Code != http.StatusOK || !handled {
		t.Fatalf("有权限应放行：code=%d handled=%v", w2.Code, handled)
	}
	// 无权限 → 403。
	raw2, _ := s.Sign("u-2", token.WithRoles("user"))
	req2 := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req2.Header.Set("Authorization", "Bearer "+raw2)
	w3 := httptest.NewRecorder()
	c3 := webx.NewContext(w3, req2)
	handled = false
	c3.SetHandlers([]webx.HandlerFunc{mw, perm, func(c *webx.Context) { handled = true }})
	c3.Run()
	if w3.Code != http.StatusForbidden || handled {
		t.Fatalf("无权限应 403：code=%d handled=%v", w3.Code, handled)
	}
}

// TestRequireRole 覆盖角色中间件。
func TestRequireRole(t *testing.T) {
	s := newSigner(t)
	rb := rbac.New()
	_ = rb.AddRole("admin")
	mw := Auth(s)
	roleMW := RequireRole(rb, "admin")
	handled := false
	// 无认证 → 401。
	w, _ := runChain(t, http.MethodGet, roleMW, func(c *webx.Context) { handled = true })
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("未认证应 401：%d", w.Code)
	}
	// 命中角色 → 放行。
	raw, _ := s.Sign("u-1", token.WithRoles("admin"))
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	w2 := httptest.NewRecorder()
	c2 := webx.NewContext(w2, req)
	handled = false
	c2.SetHandlers([]webx.HandlerFunc{mw, roleMW, func(c *webx.Context) { handled = true }})
	c2.Run()
	if w2.Code != http.StatusOK || !handled {
		t.Fatalf("命中角色应放行：code=%d handled=%v", w2.Code, handled)
	}
	// 未命中角色 → 403。
	raw2, _ := s.Sign("u-2", token.WithRoles("user"))
	req2 := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req2.Header.Set("Authorization", "Bearer "+raw2)
	w3 := httptest.NewRecorder()
	c3 := webx.NewContext(w3, req2)
	handled = false
	c3.SetHandlers([]webx.HandlerFunc{mw, roleMW, func(c *webx.Context) { handled = true }})
	c3.Run()
	if w3.Code != http.StatusForbidden || handled {
		t.Fatalf("未命中角色应 403：code=%d handled=%v", w3.Code, handled)
	}
}

// TestCSRF 覆盖 CSRF 中间件全部分支。
func TestCSRF(t *testing.T) {
	mw := CSRF("csrf", "X-CSRF-Token")
	handled := false
	// GET 放行。
	w, _ := runChain(t, http.MethodGet, mw, func(c *webx.Context) { handled = true })
	if w.Code != http.StatusOK || !handled {
		t.Fatalf("GET 应放行：code=%d handled=%v", w.Code, handled)
	}
	// 显式跳过的方法放行。
	mw2 := CSRF("csrf", "X-CSRF-Token", http.MethodPost)
	handled = false
	w2, _ := runChain(t, http.MethodPost, mw2, func(c *webx.Context) { handled = true })
	if w2.Code != http.StatusOK || !handled {
		t.Fatalf("显式跳过应放行：code=%d handled=%v", w2.Code, handled)
	}
	// 缺 Cookie → 403。
	handled = false
	w3, _ := runChain(t, http.MethodPost, mw, func(c *webx.Context) { handled = true })
	if w3.Code != http.StatusForbidden || handled {
		t.Fatalf("缺 Cookie 应 403：code=%d handled=%v", w3.Code, handled)
	}
	// Cookie 与头不匹配 → 403。
	req := httptest.NewRequest(http.MethodPost, "/ping", nil)
	req.AddCookie(&http.Cookie{Name: "csrf", Value: "abc"})
	req.Header.Set("X-CSRF-Token", "def")
	w4 := httptest.NewRecorder()
	c4 := webx.NewContext(w4, req)
	handled = false
	c4.SetHandlers([]webx.HandlerFunc{mw, func(c *webx.Context) { handled = true }})
	c4.Run()
	if w4.Code != http.StatusForbidden || handled {
		t.Fatalf("不匹配应 403：code=%d handled=%v", w4.Code, handled)
	}
	// 匹配 → 放行。
	req5 := httptest.NewRequest(http.MethodPost, "/ping", nil)
	req5.AddCookie(&http.Cookie{Name: "csrf", Value: "abc"})
	req5.Header.Set("X-CSRF-Token", "abc")
	w5 := httptest.NewRecorder()
	c5 := webx.NewContext(w5, req5)
	handled = false
	c5.SetHandlers([]webx.HandlerFunc{mw, func(c *webx.Context) { handled = true }})
	c5.Run()
	if w5.Code != http.StatusOK || !handled {
		t.Fatalf("匹配应放行：code=%d handled=%v", w5.Code, handled)
	}
}

// TestBearerToken 覆盖令牌提取分支。
func TestBearerToken(t *testing.T) {
	if _, ok := bearerToken("Basic abc"); ok {
		t.Fatal("非 Bearer 不应通过")
	}
	if _, ok := bearerToken("Bearer "); ok {
		t.Fatal("空令牌不应通过")
	}
	raw, ok := bearerToken("Bearer  abc  ")
	if !ok || raw != "abc" {
		t.Fatalf("令牌提取不符：%q %v", raw, ok)
	}
}

// TestMiddlewarePanics 覆盖其余 panic 分支。
func TestMiddlewarePanics(t *testing.T) {
	rb := rbac.New()
	for name, fn := range map[string]func(){
		"RequirePermission 空权限": func() { _ = RequirePermission(rb, "") },
		"RequireRole nil":       func() { _ = RequireRole(nil, "admin") },
		"RequireRole 空角色":       func() { _ = RequireRole(rb, "") },
		"CSRF 空 Cookie 名":       func() { _ = CSRF("", "X") },
		"CSRF 空请求头名":            func() { _ = CSRF("c", "") },
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
