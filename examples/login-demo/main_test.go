package main

import (
	"bytes"
	"encoding/json"
	testx "github.com/lcylpzls/testx"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lcylpzls/authx/mfa"
	"github.com/lcylpzls/webx/v2"
)

// TestRun 验证演示应用可完整装配。
func TestRun(t *testing.T) {
	if err := run(); err != nil {
		t.Fatalf("示例装配失败：%v", err)
	}
}

// runChain 在内存中执行路由处理器链。
func runChain(route webx.Route, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	c := webx.NewContext(w, req)
	c.SetHandlers(append(append([]webx.HandlerFunc{}, route.Middleware...), route.Handler))
	c.Run()
	return w
}

// routeOf 按方法与路径查找路由。
func routeOf(routes []webx.Route, method, path string) webx.Route {
	for _, r := range routes {
		if r.Method == method && r.Path == path {
			return r
		}
	}
	panic("路由不存在：" + method + " " + path)
}

// TestAppFlow 覆盖注册 → 登录 → 会话 → JWT → RBAC → MFA 全链路。
func TestAppFlow(t *testing.T) {
	routes, deps, err := newApp()
	testx.RequireNoError(t, err)

	defer deps.Close()

	postJSON := func(route webx.Route, body any, cookies []*http.Cookie) *httptest.ResponseRecorder {
		data, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, route.Path, bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "http://localhost:8080")
		for _, ck := range cookies {
			req.AddCookie(ck)
		}
		if len(cookies) > 0 {
			req.Header.Set("X-CSRF-Token", cookies[0].Value)
		}
		return runChain(route, req)
	}

	// 1. 获取 CSRF 令牌。
	csrfRoute := routeOf(routes, http.MethodGet, "/api/csrf")
	w := runChain(csrfRoute, httptest.NewRequest(http.MethodGet, "/api/csrf", nil))
	cookies := w.Result().Cookies()
	var csrf *http.Cookie
	for _, ck := range cookies {
		if ck.Name == csrfCookie {
			csrf = ck
		}
	}
	testx.RequireNotNil(t, csrf)

	csrfOnly := []*http.Cookie{csrf}

	// 2. 注册普通用户。
	regRoute := routeOf(routes, http.MethodPost, "/api/register")
	w = postJSON(regRoute, map[string]string{"username": "alice", "password": "Alice123!"}, csrfOnly)
	testx.RequireEqual(t, w.Code, http.StatusOK)

	if _, ok := deps.users.byUsername("alice"); !ok {
		t.Fatal("注册用户应已存储")
	}
	// 重复注册。
	w = postJSON(regRoute, map[string]string{"username": "alice", "password": "Alice123!"}, csrfOnly)
	testx.RequireEqual(t, w.Code, http.StatusConflict)

	// 弱密码。
	w = postJSON(regRoute, map[string]string{"username": "bob", "password": "weak"}, csrfOnly)
	testx.RequireEqual(t, w.Code, http.StatusBadRequest)

	// 3. 登录 alice，收集会话 Cookie 与 JWT。
	loginRoute := routeOf(routes, http.MethodPost, "/api/login")
	loginResp := postJSON(loginRoute, map[string]string{"username": "alice", "password": "Alice123!"}, csrfOnly)
	testx.RequireEqual(t, loginResp.Code, http.StatusOK)

	var loginData struct {
		Data struct {
			AccessToken string `json:"access_token"`
			UserID      string `json:"user_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(loginResp.Body.Bytes(), &loginData); err != nil || loginData.Data.AccessToken == "" {
		t.Fatalf("登录响应应含令牌：%v %s", err, loginResp.Body.String())
	}
	// 登录失败累计。
	w = postJSON(loginRoute, map[string]string{"username": "alice", "password": "wrong"}, csrfOnly)
	testx.RequireEqual(t, w.Code, http.StatusUnauthorized)

	// 4. JWT 访问 /api/me 与 /api/admin。
	meRoute := routeOf(routes, http.MethodGet, "/api/me")
	reqMe := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	reqMe.Header.Set("Authorization", "Bearer "+loginData.Data.AccessToken)
	w = runChain(meRoute, reqMe)
	if w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(`"user_id"`)) {
		t.Fatalf("me 应返回用户：%d %s", w.Code, w.Body.String())
	}
	adminRoute := routeOf(routes, http.MethodGet, "/api/admin")
	reqAdmin := httptest.NewRequest(http.MethodGet, "/api/admin", nil)
	reqAdmin.Header.Set("Authorization", "Bearer "+loginData.Data.AccessToken)
	w = runChain(adminRoute, reqAdmin)
	testx.RequireEqual(t, w.Code, http.StatusForbidden)

	// 5. 种子管理员登录并访问管理接口。
	adminLogin := postJSON(loginRoute, map[string]string{"username": "admin", "password": "admin123!"}, csrfOnly)
	testx.RequireEqual(t, adminLogin.Code, http.StatusOK)

	adminSess := adminLogin.Result().Cookies()
	var sidCookie *http.Cookie
	for _, ck := range adminSess {
		if ck.Name == sessCookie {
			sidCookie = ck
		}
	}
	testx.RequireNotNil(t, sidCookie)

	var adminData struct {
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(adminLogin.Body.Bytes(), &adminData); err != nil {
		t.Fatal(err)
	}
	reqAdmin2 := httptest.NewRequest(http.MethodGet, "/api/admin", nil)
	reqAdmin2.Header.Set("Authorization", "Bearer "+adminData.Data.AccessToken)
	w = runChain(adminRoute, reqAdmin2)
	testx.RequireEqual(t, w.Code, http.StatusOK)

	// 6. MFA 配置与校验（管理员）。
	setupRoute := routeOf(routes, http.MethodGet, "/api/mfa/setup")
	reqSetup := httptest.NewRequest(http.MethodGet, "/api/mfa/setup", nil)
	reqSetup.AddCookie(sidCookie)
	w = runChain(setupRoute, reqSetup)
	testx.RequireEqual(t, w.Code, http.StatusOK)

	var setupData struct {
		Data struct {
			Secret string `json:"secret"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &setupData); err != nil || setupData.Data.Secret == "" {
		t.Fatalf("MFA 密钥缺失：%v %s", err, w.Body.String())
	}
	code, err := mfa.GenerateCode(setupData.Data.Secret, time.Now())
	testx.RequireNoError(t, err)

	verifyRoute := routeOf(routes, http.MethodPost, "/api/mfa/verify")
	body, _ := json.Marshal(map[string]string{"code": code})
	reqVerify := httptest.NewRequest(http.MethodPost, "/api/mfa/verify", bytes.NewReader(body))
	reqVerify.AddCookie(sidCookie)
	w = runChain(verifyRoute, reqVerify)
	testx.RequireEqual(t, w.Code, http.StatusOK)

	// 错误验证码。
	badBody, _ := json.Marshal(map[string]string{"code": "000000"})
	reqBad := httptest.NewRequest(http.MethodPost, "/api/mfa/verify", bytes.NewReader(badBody))
	reqBad.AddCookie(sidCookie)
	w = runChain(verifyRoute, reqBad)
	testx.RequireEqual(t, w.Code, http.StatusBadRequest)

}
