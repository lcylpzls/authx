package oauth2

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	testx "github.com/lcylpzls/testx"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	gooauth2 "github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/errx"
	"github.com/lcylpzls/webx/v2"
)

const (
	testClientID     = "111111"
	testClientSecret = "11111111"
	testRedirect     = "http://localhost:9999/cb"
)

// newTestOAuthServer 构造测试授权服务与处理器。
func newTestOAuthServer(t *testing.T) *http.ServeMux {
	t.Helper()
	s, err := NewServer(ServerConfig{
		ClientID:     testClientID,
		ClientSecret: testClientSecret,
		RedirectURL:  testRedirect,
	})
	testx.RequireNoError(t, err)

	s.SetUserAuthorizationHandlerFromContext()
	mux := http.NewServeMux()
	mux.Handle("/authorize", s.AuthorizeHandler())
	mux.Handle("/token", s.TokenHandler())
	return mux
}

// s256Challenge 计算 PKCE S256 挑战值。
func s256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// TestNewServerErrors 覆盖服务端配置校验。
func TestNewServerErrors(t *testing.T) {
	if _, err := NewServer(ServerConfig{RedirectURL: testRedirect}); err == nil ||
		!errx.Is(err, authx.CodeOAuth2ConfigInvalid) {
		t.Fatalf("空 ClientID 应报错，实际：%v", err)
	}
	if _, err := NewServer(ServerConfig{ClientID: testClientID}); err == nil ||
		!errx.Is(err, authx.CodeOAuth2ConfigInvalid) {
		t.Fatalf("空 RedirectURL 应报错，实际：%v", err)
	}
	if _, err := NewServer(ServerConfig{ClientID: testClientID, RedirectURL: testRedirect},
		WithClientBasicAuth()); err != nil {
		t.Fatalf("Basic Auth 选项应可用：%v", err)
	}
	if _, err := NewServer(ServerConfig{ClientID: testClientID, RedirectURL: testRedirect},
		func(*Server) error { return errors.New("选项失败") }); err == nil {
		t.Fatal("返回错误的选项应导致构造失败")
	}
}

// recordingClientStore 记录查询的自定义客户端存储。
type recordingClientStore struct {
	called bool
}

func (r *recordingClientStore) GetByID(_ context.Context, id string) (gooauth2.ClientInfo, error) {
	r.called = true
	return &models.Client{ID: id, Secret: "s", Domain: testRedirect}, nil
}

// TestServerStores 覆盖可插拔存储选项。
func TestServerStores(t *testing.T) {
	if _, err := NewServer(ServerConfig{ClientID: testClientID, RedirectURL: testRedirect},
		WithClientStore(nil)); err == nil || !errx.Is(err, authx.CodeOAuth2ConfigInvalid) {
		t.Fatalf("空客户端存储应报错，实际：%v", err)
	}
	if _, err := NewServer(ServerConfig{ClientID: testClientID, RedirectURL: testRedirect},
		WithTokenStore(nil)); err == nil || !errx.Is(err, authx.CodeOAuth2ConfigInvalid) {
		t.Fatalf("空令牌存储应报错，实际：%v", err)
	}
	// 注入 go-oauth2 自带内存实现。
	memTokens, err := store.NewMemoryTokenStore()
	testx.RequireNoError(t, err)

	if _, err := NewServer(ServerConfig{ClientID: testClientID, RedirectURL: testRedirect},
		WithClientStore(store.NewClientStore()),
		WithTokenStore(memTokens)); err != nil {
		t.Fatalf("注入内存存储应成功：%v", err)
	}
	// 注入自定义客户端存储并验证生效。
	rec := &recordingClientStore{}
	s2, err := NewServer(ServerConfig{ClientID: testClientID, RedirectURL: testRedirect},
		WithClientStore(rec))
	testx.RequireNoError(t, err)

	cli, err := s2.manager.GetClient(context.Background(), "custom")
	if err != nil || !rec.called || cli.GetID() != "custom" {
		t.Fatalf("自定义客户端存储未生效：cli=%v err=%v called=%v", cli, err, rec.called)
	}
}

// TestAuthorizationCodePKCEFlow 覆盖授权码 + PKCE + 刷新令牌全流程。
func TestAuthorizationCodePKCEFlow(t *testing.T) {
	mux := newTestOAuthServer(t)
	verifier := "test-verifier-0123456789abcdef"

	// 1. 授权端点：登录用户 + S256 挑战 → 302 带 code。
	authURL := "/authorize?response_type=code&client_id=" + testClientID +
		"&redirect_uri=" + url.QueryEscape(testRedirect) +
		"&state=xyz&code_challenge=" + s256Challenge(verifier) + "&code_challenge_method=S256"
	req := httptest.NewRequest(http.MethodGet, authURL, nil)
	req = req.WithContext(WithUserID(req.Context(), "u-1"))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	resp := w.Result()
	testx.RequireEqual(t, resp.StatusCode, http.StatusFound)

	loc, err := url.Parse(resp.Header.Get("Location"))
	testx.RequireNoError(t, err)

	code := loc.Query().Get("code")
	if code == "" || loc.Query().Get("state") != "xyz" {
		t.Fatalf("回调参数不符：%s", resp.Header.Get("Location"))
	}

	// 2. 令牌端点：授权码 + verifier 换 access/refresh。
	tokenJSON := exchange(t, mux, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {testRedirect},
		"client_id":     {testClientID},
		"client_secret": {testClientSecret},
		"code_verifier": {verifier},
	})
	access := tokenJSON["access_token"].(string)
	refresh := tokenJSON["refresh_token"].(string)
	if access == "" || refresh == "" {
		t.Fatalf("令牌字段缺失：%v", tokenJSON)
	}

	// 3. 刷新令牌换新 access。
	refreshed := exchange(t, mux, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"client_id":     {testClientID},
		"client_secret": {testClientSecret},
	})
	if refreshed["access_token"].(string) == "" {
		t.Fatalf("刷新令牌响应缺失：%v", refreshed)
	}
}

// exchange 向令牌端点发起表单请求并解析 JSON。
func exchange(t *testing.T, mux http.Handler, form url.Values) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	testx.RequireEqual(t, w.Code, http.StatusOK)

	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("令牌响应解析失败：%v body=%s", err, w.Body.String())
	}
	return out
}

// TestOAuthErrors 覆盖授权/令牌错误分支。
func TestOAuthErrors(t *testing.T) {
	mux := newTestOAuthServer(t)
	verifier := "test-verifier-0123456789abcdef"
	base := "/authorize?response_type=code&client_id=" + testClientID +
		"&redirect_uri=" + url.QueryEscape(testRedirect) +
		"&code_challenge=" + s256Challenge(verifier) + "&code_challenge_method=S256"
	// 未登录 → 401。
	req := httptest.NewRequest(http.MethodGet, base, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	testx.RequireEqual(t, w.Code, http.StatusUnauthorized)

	// 非法 client_id → 302 重定向错误（OAuth2 规范）。
	req2 := httptest.NewRequest(http.MethodGet, strings.Replace(base, testClientID, "bad", 1), nil)
	req2 = req2.WithContext(WithUserID(req2.Context(), "u-1"))
	w2 := httptest.NewRecorder()
	mux.ServeHTTP(w2, req2)
	if w2.Code != http.StatusFound || !strings.Contains(w2.Header().Get("Location"), "error") {
		t.Fatalf("非法客户端应重定向错误：%d %s", w2.Code, w2.Header().Get("Location"))
	}
	// 错误授权码 → 400。
	req3 := httptest.NewRequest(http.MethodPost, "/token",
		strings.NewReader(url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {"bad-code"},
			"redirect_uri":  {testRedirect},
			"client_id":     {testClientID},
			"client_secret": {testClientSecret},
		}.Encode()))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w3 := httptest.NewRecorder()
	mux.ServeHTTP(w3, req3)
	if w3.Code < 400 {
		t.Fatalf("错误授权码应 4xx：%d", w3.Code)
	}
	// 错误刷新令牌 → 400。
	req4 := httptest.NewRequest(http.MethodPost, "/token",
		strings.NewReader(url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {"bad"},
			"client_id":     {testClientID},
			"client_secret": {testClientSecret},
		}.Encode()))
	req4.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w4 := httptest.NewRecorder()
	mux.ServeHTTP(w4, req4)
	if w4.Code < 400 {
		t.Fatalf("错误刷新令牌应 4xx：%d", w4.Code)
	}
}

// TestWebxHandlers 覆盖 webx 适配处理器。
func TestWebxHandlers(t *testing.T) {
	s, err := NewServer(ServerConfig{
		ClientID:     testClientID,
		ClientSecret: testClientSecret,
		RedirectURL:  testRedirect,
	})
	testx.RequireNoError(t, err)

	s.SetUserAuthorizationHandlerFromContext()
	verifier := "test-verifier-0123456789abcdef"
	authURL := "/authorize?response_type=code&client_id=" + testClientID +
		"&redirect_uri=" + url.QueryEscape(testRedirect) +
		"&state=wz&code_challenge=" + s256Challenge(verifier) + "&code_challenge_method=S256"
	req := httptest.NewRequest(http.MethodGet, authURL, nil)
	req = req.WithContext(WithUserID(req.Context(), "u-9"))
	w := httptest.NewRecorder()
	c := webx.NewContext(w, req)
	c.SetHandlers([]webx.HandlerFunc{s.AuthorizeWebxHandler()})
	c.Run()
	testx.RequireEqual(t, w.Code, http.StatusFound)

	loc, _ := url.Parse(w.Header().Get("Location"))
	code := loc.Query().Get("code")
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {testRedirect},
		"client_id":     {testClientID},
		"client_secret": {testClientSecret},
		"code_verifier": {verifier},
	}
	req2 := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	c2 := webx.NewContext(w2, req2)
	c2.SetHandlers([]webx.HandlerFunc{s.TokenWebxHandler()})
	c2.Run()
	if w2.Code != http.StatusOK || !strings.Contains(w2.Body.String(), "access_token") {
		t.Fatalf("webx 令牌应 200：%d body=%s", w2.Code, w2.Body.String())
	}
	// webx 授权端点未登录 → 401。
	req3 := httptest.NewRequest(http.MethodGet, authURL, nil)
	w3 := httptest.NewRecorder()
	c3 := webx.NewContext(w3, req3)
	c3.SetHandlers([]webx.HandlerFunc{s.AuthorizeWebxHandler()})
	c3.Run()
	testx.RequireEqual(t, w3.Code, http.StatusUnauthorized)

}

// TestCustomUserHandler 覆盖自定义用户解析器。
func TestCustomUserHandler(t *testing.T) {
	s, err := NewServer(ServerConfig{
		ClientID:     testClientID,
		ClientSecret: testClientSecret,
		RedirectURL:  testRedirect,
	})
	testx.RequireNoError(t, err)

	s.SetUserAuthorizationHandler(func(r *http.Request) (string, error) { return "u-custom", nil })
	authURL := "/authorize?response_type=code&client_id=" + testClientID +
		"&redirect_uri=" + url.QueryEscape(testRedirect) + "&state=cs"
	req := httptest.NewRequest(http.MethodGet, authURL, nil)
	w := httptest.NewRecorder()
	s.AuthorizeHandler().ServeHTTP(w, req)
	testx.RequireEqual(t, w.Code, http.StatusFound)

}
