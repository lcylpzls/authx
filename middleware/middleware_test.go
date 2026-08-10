package middleware

import (
	"errors"
	testx "github.com/lcylpzls/testx"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/authx/rbac"
	"github.com/lcylpzls/authx/token"
	"github.com/lcylpzls/errx"
	"github.com/lcylpzls/webx/v2"
)

// newSigner 构造测试签发器。
func newSigner(t *testing.T) *token.Signer {
	t.Helper()
	s, err := token.NewHS256([]byte("0123456789abcdef0123456789abcdef"))
	testx.RequireNoError(t, err)

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
	if got := w.Header().Get("WWW-Authenticate"); got != `Bearer realm="console"` {
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
	testx.RequireNoError(t, err)

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
	testx.RequireEqual(t, w.Code, http.StatusUnauthorized)

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
	testx.RequireEqual(t, w.Code, http.StatusUnauthorized)

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
	if _, ok := bearerToken("Bearer " + strings.Repeat("x", maxBearerLength+1)); ok {
		t.Fatal("超长令牌不应通过")
	}
	raw, ok := bearerToken("Bearer  abc  ")
	if !ok || raw != "abc" {
		t.Fatalf("令牌提取不符：%q %v", raw, ok)
	}
}

// TestAuthRealmEscape 覆盖 realm 引号与反斜杠转义。
func TestAuthRealmEscape(t *testing.T) {
	s := newSigner(t)
	mw := Auth(s, WithRealm(`con"sole\`))
	w, _ := runChain(t, http.MethodGet, mw)
	if got := w.Header().Get("WWW-Authenticate"); got != `Bearer realm="con\"sole\\"` {
		t.Fatalf("realm 转义不符：%q", got)
	}
}

// TestValidateCSRFToken 覆盖常量时间比较与长度防御分支。
func TestValidateCSRFToken(t *testing.T) {
	if !ValidateCSRFToken("abc", "abc") {
		t.Fatal("相同令牌应通过")
	}
	if ValidateCSRFToken("abc", "abd") {
		t.Fatal("不同令牌不应通过")
	}
	if ValidateCSRFToken("", "abc") || ValidateCSRFToken("abc", "") {
		t.Fatal("空值不应通过")
	}
	if ValidateCSRFToken(strings.Repeat("x", maxCSRFTokenLength+1), "abc") ||
		ValidateCSRFToken("abc", strings.Repeat("x", maxCSRFTokenLength+1)) {
		t.Fatal("超长令牌不应通过")
	}
}

// TestGenerateCSRFTokenError 覆盖随机源失败分支。
func TestGenerateCSRFTokenError(t *testing.T) {
	token, err := GenerateCSRFToken()
	if err != nil || token == "" {
		t.Fatalf("正常生成应成功：%q %v", token, err)
	}
	orig := randRead
	randRead = func(b []byte) (int, error) { return 0, errors.New("随机源故障") }
	defer func() { randRead = orig }()
	if _, err := GenerateCSRFToken(); err == nil || !errx.Is(err, authx.CodeCSRFGenerationFailed) {
		t.Fatalf("随机源故障应报错，实际：%v", err)
	}
}

// TestCSRFProtect 覆盖双提交 Cookie 中间件全部分支。
func TestCSRFProtect(t *testing.T) {
	mw := CSRFProtect("csrf", "X-CSRF-Token",
		WithCSRFSecure(false), WithCSRFHTTPOnly(false), WithCSRFPath("/app"),
		WithCSRFSameSite(http.SameSiteStrictMode))
	handled := false
	// 首次 GET：无 Cookie → 种令牌并放行。
	w, _ := runChain(t, http.MethodGet, mw, func(c *webx.Context) { handled = true })
	if w.Code != http.StatusOK || !handled {
		t.Fatalf("首次 GET 应放行并种 Cookie：code=%d handled=%v", w.Code, handled)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "csrf" || cookies[0].Value == "" ||
		cookies[0].Path != "/app" || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("CSRF Cookie 属性不符：%+v", cookies)
	}
	token := cookies[0].Value
	// 安全方法放行（无需请求头）。
	reqSafe := httptest.NewRequest(http.MethodGet, "/ping", nil)
	reqSafe.AddCookie(&http.Cookie{Name: "csrf", Value: token})
	wSafe := httptest.NewRecorder()
	cSafe := webx.NewContext(wSafe, reqSafe)
	handled = false
	cSafe.SetHandlers([]webx.HandlerFunc{mw, func(c *webx.Context) { handled = true }})
	cSafe.Run()
	testx.RequireTrue(t, handled)

	// 非安全方法匹配 → 放行。
	reqOK := httptest.NewRequest(http.MethodPost, "/ping", nil)
	reqOK.AddCookie(&http.Cookie{Name: "csrf", Value: token})
	reqOK.Header.Set("X-CSRF-Token", token)
	wOK := httptest.NewRecorder()
	cOK := webx.NewContext(wOK, reqOK)
	handled = false
	cOK.SetHandlers([]webx.HandlerFunc{mw, func(c *webx.Context) { handled = true }})
	cOK.Run()
	if wOK.Code != http.StatusOK || !handled {
		t.Fatalf("匹配应放行：code=%d handled=%v", wOK.Code, handled)
	}
	// 不匹配 → 403。
	reqBad := httptest.NewRequest(http.MethodPost, "/ping", nil)
	reqBad.AddCookie(&http.Cookie{Name: "csrf", Value: token})
	reqBad.Header.Set("X-CSRF-Token", "wrong")
	wBad := httptest.NewRecorder()
	cBad := webx.NewContext(wBad, reqBad)
	handled = false
	cBad.SetHandlers([]webx.HandlerFunc{mw, func(c *webx.Context) { handled = true }})
	cBad.Run()
	if wBad.Code != http.StatusForbidden || handled {
		t.Fatalf("不匹配应 403：code=%d handled=%v", wBad.Code, handled)
	}
	// 非安全方法但无 Cookie → 403（已有 Cookie 缺失时不会重复种 Cookie？会种新 Cookie 但校验失败）。
	reqNoCookie := httptest.NewRequest(http.MethodPost, "/ping", nil)
	reqNoCookie.Header.Set("X-CSRF-Token", token)
	wNoCookie := httptest.NewRecorder()
	cNoCookie := webx.NewContext(wNoCookie, reqNoCookie)
	handled = false
	cNoCookie.SetHandlers([]webx.HandlerFunc{mw, func(c *webx.Context) { handled = true }})
	cNoCookie.Run()
	if wNoCookie.Code != http.StatusForbidden || handled {
		t.Fatalf("缺 Cookie 非安全方法应 403：code=%d handled=%v", wNoCookie.Code, handled)
	}
}

// TestCSRFProtectGenerationFailure 覆盖令牌生成失败返回 500。
func TestCSRFProtectGenerationFailure(t *testing.T) {
	orig := randRead
	randRead = func(b []byte) (int, error) { return 0, errors.New("随机源故障") }
	defer func() { randRead = orig }()
	mw := CSRFProtect("csrf", "X-CSRF-Token")
	w, _ := runChain(t, http.MethodGet, mw)
	testx.RequireEqual(t, w.Code, http.StatusInternalServerError)

}

// TestCSRFProtectPanics 覆盖 CSRFProtect 配置 panic。
func TestCSRFProtectPanics(t *testing.T) {
	for name, fn := range map[string]func(){
		"空 Cookie 名": func() { _ = CSRFProtect("", "X") },
		"空请求头名":      func() { _ = CSRFProtect("c", "") },
		"零 TTL":      func() { _ = CSRFProtect("c", "X", WithCSRFTTL(0)) },
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

// TestCSRFAllowedOrigins 覆盖 Origin/Referer 校验分支。
func TestCSRFAllowedOrigins(t *testing.T) {
	mw := CSRFProtect("csrf", "X-CSRF-Token",
		WithCSRFAllowedOrigins("https://app.example.com"), WithCSRFSecure(false))
	token, err := GenerateCSRFToken()
	testx.RequireNoError(t, err)

	run := func(origin, referer string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/ping", nil)
		req.AddCookie(&http.Cookie{Name: "csrf", Value: token})
		req.Header.Set("X-CSRF-Token", token)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if referer != "" {
			req.Header.Set("Referer", referer)
		}
		w := httptest.NewRecorder()
		c := webx.NewContext(w, req)
		c.SetHandlers([]webx.HandlerFunc{mw})
		c.Run()
		return w
	}
	if w := run("https://app.example.com", ""); w.Code != http.StatusOK {
		t.Fatalf("匹配 Origin 应放行：%d", w.Code)
	}
	if w := run("https://evil.example.com", ""); w.Code != http.StatusForbidden {
		t.Fatalf("不匹配 Origin 应 403：%d", w.Code)
	}
	if w := run("", "https://app.example.com/path"); w.Code != http.StatusOK {
		t.Fatalf("匹配 Referer 应放行：%d", w.Code)
	}
	if w := run("", "https://evil.example.com/path"); w.Code != http.StatusForbidden {
		t.Fatalf("不匹配 Referer 应 403：%d", w.Code)
	}
	if w := run("", "://bad-url"); w.Code != http.StatusForbidden {
		t.Fatalf("非法 Referer 应 403：%d", w.Code)
	}
	if w := run("", "no-scheme/path"); w.Code != http.StatusForbidden {
		t.Fatalf("无协议 Referer 应 403：%d", w.Code)
	}
	if w := run("", strings.Repeat("x", maxOriginLength+1)); w.Code != http.StatusForbidden {
		t.Fatalf("超长 Referer 应 403：%d", w.Code)
	}
	if w := run(strings.Repeat("x", maxOriginLength+1), ""); w.Code != http.StatusForbidden {
		t.Fatalf("超长 Origin 应 403：%d", w.Code)
	}
	// 未配置允许列表时跳过来源校验。
	mwPlain := CSRFProtect("csrf", "X-CSRF-Token", WithCSRFSecure(false))
	req := httptest.NewRequest(http.MethodPost, "/ping", nil)
	req.AddCookie(&http.Cookie{Name: "csrf", Value: token})
	req.Header.Set("X-CSRF-Token", token)
	w := httptest.NewRecorder()
	c := webx.NewContext(w, req)
	c.SetHandlers([]webx.HandlerFunc{mwPlain})
	c.Run()
	testx.RequireEqual(t, w.Code, http.StatusOK)

}

// TestCSRFClockOption 覆盖注入时钟与 nil 回退。
func TestCSRFClockOption(t *testing.T) {
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	mw := CSRFProtect("csrf", "X-CSRF-Token",
		WithCSRFClock(func() time.Time { return now }), WithCSRFSecure(false))
	w, _ := runChain(t, http.MethodGet, mw)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Expires.Equal(now.Add(defaultCSRFTTL)) {
		t.Fatalf("CSRF Cookie 过期时间应使用注入时钟：%+v", cookies)
	}
	// nil 时钟回退到 time.Now，不应 panic。
	mwNil := CSRFProtect("csrf", "X-CSRF-Token", WithCSRFClock(nil), WithCSRFSecure(false))
	w2, _ := runChain(t, http.MethodGet, mwNil)
	testx.RequireEqual(t, w2.Code, http.StatusOK)

}

// TestErrorResponseFrom 覆盖错误响应体提取。
func TestErrorResponseFrom(t *testing.T) {
	resp := errorResponseFrom(authx.ErrTokenMissing)
	if resp.Code != string(authx.CodeTokenMissing) || resp.Kind != "unauthorized" ||
		!strings.Contains(resp.Message, "缺少访问令牌") {
		t.Fatalf("errx 错误提取不符：%+v", resp)
	}
	plain := errorResponseFrom(errors.New("普通错误"))
	if plain.Code != "" || plain.Kind != "unknown" || plain.Message != "普通错误" {
		t.Fatalf("普通错误回退不符：%+v", plain)
	}
	nilResp := errorResponseFrom(nil)
	if nilResp.Message != "内部错误" || nilResp.Kind != "unknown" {
		t.Fatalf("nil 错误回退不符：%+v", nilResp)
	}
}

// TestDefaultErrorHandler 覆盖默认处理器输出结构化 JSON。
func TestDefaultErrorHandler(t *testing.T) {
	w, c := runChain(t, http.MethodGet)
	DefaultErrorHandler(c, http.StatusForbidden, authx.ErrForbidden)
	testx.RequireEqual(t, w.Code, http.StatusForbidden)

	body := w.Body.String()
	if !strings.Contains(body, `"authx_forbidden"`) || !strings.Contains(body, `"forbidden"`) {
		t.Fatalf("响应应含结构化错误：%s", body)
	}
}

// TestAuthErrorHandler 覆盖自定义认证错误处理器。
func TestAuthErrorHandler(t *testing.T) {
	s := newSigner(t)
	type call struct {
		status int
		err    error
	}
	calls := make([]call, 0, 2)
	handler := func(c *webx.Context, status int, err error) {
		calls = append(calls, call{status: status, err: err})
		c.AbortWithStatusJSON(status, err.Error(), nil)
	}
	mw := Auth(s, WithAuthErrorHandler(handler))
	// 无令牌。
	w, _ := runChain(t, http.MethodGet, mw)
	if w.Code != http.StatusUnauthorized || len(calls) != 1 || !errx.Is(calls[0].err, authx.CodeTokenMissing) {
		t.Fatalf("无令牌应调用自定义处理器：code=%d calls=%+v", w.Code, calls)
	}
	// 无效令牌。
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req.Header.Set("Authorization", "Bearer bad.token")
	w2 := httptest.NewRecorder()
	c2 := webx.NewContext(w2, req)
	c2.SetHandlers([]webx.HandlerFunc{mw})
	c2.Run()
	if w2.Code != http.StatusUnauthorized || len(calls) != 2 || !errx.Is(calls[1].err, authx.CodeTokenSignature) {
		t.Fatalf("无效令牌应调用自定义处理器：code=%d calls=%+v", w2.Code, calls)
	}
}

// TestWithAuthErrorHandlerPanic 覆盖 nil 处理器 panic。
func TestWithAuthErrorHandlerPanic(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("nil 处理器应 panic")
		}
	}()
	_ = Auth(newSigner(t), WithAuthErrorHandler(nil))
}

// TestCSRFErrorHandler 覆盖 CSRF 自定义错误处理器。
func TestCSRFErrorHandler(t *testing.T) {
	type call struct {
		status int
		err    error
	}
	calls := make([]call, 0, 1)
	handler := func(c *webx.Context, status int, err error) {
		calls = append(calls, call{status: status, err: err})
		c.AbortWithStatusJSON(status, err.Error(), nil)
	}
	// 不匹配 → 403。
	mw := CSRFProtect("csrf", "X-CSRF-Token", WithCSRFErrorHandler(handler), WithCSRFSecure(false))
	req := httptest.NewRequest(http.MethodPost, "/ping", nil)
	req.AddCookie(&http.Cookie{Name: "csrf", Value: "abc"})
	req.Header.Set("X-CSRF-Token", "def")
	w := httptest.NewRecorder()
	c := webx.NewContext(w, req)
	c.SetHandlers([]webx.HandlerFunc{mw})
	c.Run()
	if w.Code != http.StatusForbidden || len(calls) != 1 || !errx.Is(calls[0].err, authx.CodeCSRFMismatch) {
		t.Fatalf("CSRF 失败应调用自定义处理器：code=%d calls=%+v", w.Code, calls)
	}
	// 生成失败 → 500。
	orig := randRead
	randRead = func(b []byte) (int, error) { return 0, errors.New("随机源故障") }
	defer func() { randRead = orig }()
	mw2 := CSRFProtect("csrf", "X-CSRF-Token", WithCSRFErrorHandler(handler))
	w2, _ := runChain(t, http.MethodGet, mw2)
	if w2.Code != http.StatusInternalServerError || len(calls) != 2 ||
		!errx.Is(calls[1].err, authx.CodeCSRFGenerationFailed) {
		t.Fatalf("生成失败应调用自定义处理器：code=%d calls=%+v", w2.Code, calls)
	}
}

// TestWithCSRFErrorHandlerPanic 覆盖 nil 处理器 panic。
func TestWithCSRFErrorHandlerPanic(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("nil 处理器应 panic")
		}
	}()
	_ = CSRFProtect("c", "X", WithCSRFErrorHandler(nil))
}

// TestRequirePermissionStructured 覆盖 403 结构化输出。
func TestRequirePermissionStructured(t *testing.T) {
	rb := rbac.New()
	_ = rb.AddRole("user", "order:read")
	s := newSigner(t)
	raw, _ := s.Sign("u-1", token.WithRoles("user"))
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	c := webx.NewContext(w, req)
	c.SetHandlers([]webx.HandlerFunc{
		Auth(s),
		RequirePermission(rb, "order:write"),
	})
	c.Run()
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "authx_forbidden") {
		t.Fatalf("403 应结构化输出：code=%d body=%s", w.Code, w.Body.String())
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
