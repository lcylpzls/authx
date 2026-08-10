package oauth2

import (
	"context"
	testx "github.com/lcylpzls/testx"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/errx"
	xoauth2 "golang.org/x/oauth2"
)

// mockProvider 模拟第三方授权服务器。
func mockProvider(t *testing.T) (string, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authorize":
			http.Redirect(w, r, "/cb?code=mock-code", http.StatusFound)
		case "/token":
			if r.FormValue("grant_type") == "refresh_token" {
				if r.FormValue("refresh_token") != "rt-1" {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"at-2","token_type":"Bearer","expires_in":3600,"refresh_token":"rt-2"}`))
				return
			}
			if r.FormValue("code") != "good-code" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
				return
			}
			if r.FormValue("code_verifier") != "" && r.FormValue("code_verifier") != "test-verifier" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"at-1","token_type":"Bearer","expires_in":3600,"refresh_token":"rt-1"}`))
		case "/userinfo":
			if r.Header.Get("Authorization") != "Bearer at-1" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sub":"u-1","name":"张三"}`))
		case "/bad-json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`not-json`))
		case "/error":
			w.WriteHeader(http.StatusInternalServerError)
		case "/huge":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sub":"` + strings.Repeat("x", maxUserInfoBytes) + `"}`))
		case "/truncated":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Length", "100")
			_, _ = w.Write([]byte(`{"sub":"short"}`))
		}
	}))
	return srv.URL, srv
}

// testClient 构造指向 mock 的客户端。
func testClient(t *testing.T, base string, withUserInfo bool) *Client {
	t.Helper()
	cfg := ProviderConfig{
		ClientID:     "web",
		ClientSecret: "secret",
		AuthURL:      base + "/authorize",
		TokenURL:     base + "/token",
		RedirectURL:  base + "/cb",
		Scopes:       []string{"openid", "profile"},
	}
	if withUserInfo {
		cfg.UserInfoURL = base + "/userinfo"
	}
	c, err := NewClient(cfg)
	testx.RequireNoError(t, err)

	return c
}

// TestNewClientErrors 覆盖配置校验。
func TestNewClientErrors(t *testing.T) {
	for name, cfg := range map[string]ProviderConfig{
		"空 ClientID": {AuthURL: "a", TokenURL: "b", RedirectURL: "c"},
		"空 AuthURL":  {ClientID: "a", TokenURL: "b", RedirectURL: "c"},
		"空 TokenURL": {ClientID: "a", AuthURL: "b", RedirectURL: "c"},
		"空 Redirect": {ClientID: "a", AuthURL: "b", TokenURL: "c"},
	} {
		if _, err := NewClient(cfg); err == nil || !errx.Is(err, authx.CodeOAuth2ConfigInvalid) {
			t.Fatalf("%s 应报配置错误，实际：%v", name, err)
		}
	}
}

// TestAuthCodeURLs 覆盖授权 URL 生成。
func TestAuthCodeURLs(t *testing.T) {
	_, srv := mockProvider(t)
	defer srv.Close()
	c := testClient(t, srv.URL, false)
	u := c.AuthCodeURL("state-1")
	parsed, err := url.Parse(u)
	testx.RequireNoError(t, err)

	q := parsed.Query()
	if q.Get("client_id") != "web" || q.Get("state") != "state-1" ||
		!strings.Contains(q.Get("redirect_uri"), "/cb") {
		t.Fatalf("授权 URL 参数不符：%s", u)
	}
	u2, verifier := c.AuthCodeURLWithPKCE("state-2")
	parsed2, _ := url.Parse(u2)
	q2 := parsed2.Query()
	if q2.Get("code_challenge") == "" || q2.Get("code_challenge_method") != "S256" || verifier == "" {
		t.Fatalf("PKCE URL 不符：%s", u2)
	}
}

// TestExchange 覆盖令牌交换成功与失败。
func TestExchange(t *testing.T) {
	base, srv := mockProvider(t)
	defer srv.Close()
	c := testClient(t, base, false)
	tok, err := c.Exchange(context.Background(), "good-code", "test-verifier")
	if err != nil || tok.AccessToken != "at-1" {
		t.Fatalf("交换失败：tok=%v err=%v", tok, err)
	}
	if _, err := c.Exchange(context.Background(), "bad-code", ""); err == nil || !errx.Is(err, authx.CodeOAuth2Invalid) {
		t.Fatalf("错误 code 应报错，实际：%v", err)
	}
}

// TestRefreshToken 覆盖客户端刷新令牌流程。
func TestRefreshToken(t *testing.T) {
	base, srv := mockProvider(t)
	defer srv.Close()
	c := testClient(t, base, false)
	tok, err := c.RefreshToken(context.Background(), "rt-1")
	if err != nil || tok.AccessToken != "at-2" {
		t.Fatalf("刷新失败：tok=%v err=%v", tok, err)
	}
	if _, err := c.RefreshToken(context.Background(), ""); err == nil ||
		!errx.Is(err, authx.CodeOAuth2ConfigInvalid) {
		t.Fatalf("空刷新令牌应报配置错误，实际：%v", err)
	}
	if _, err := c.RefreshToken(context.Background(), "rt-bad"); err == nil ||
		!errx.Is(err, authx.CodeOAuth2Invalid) {
		t.Fatalf("无效刷新令牌应报错，实际：%v", err)
	}
}

// TestUserInfo 覆盖用户信息拉取。
func TestUserInfo(t *testing.T) {
	base, srv := mockProvider(t)
	defer srv.Close()
	c := testClient(t, base, true)
	info, err := c.UserInfo(context.Background(), &xoauth2.Token{AccessToken: "at-1"})
	testx.RequireNoError(t, err)

	if info["sub"] != "u-1" || info["name"] != "张三" {
		t.Fatalf("用户信息不符：%v", info)
	}
	noInfo := testClient(t, base, false)
	if _, err := noInfo.UserInfo(context.Background(), &xoauth2.Token{AccessToken: "at-1"}); err == nil ||
		!errx.Is(err, authx.CodeOAuth2ConfigInvalid) {
		t.Fatalf("未配置端点应报错，实际：%v", err)
	}
	badToken := &xoauth2.Token{AccessToken: "wrong"}
	if _, err := c.UserInfo(context.Background(), badToken); err == nil || !errx.Is(err, authx.CodeOAuth2Invalid) {
		t.Fatalf("非 200 应报错，实际：%v", err)
	}
	// 模拟解析失败：直接换 userinfo URL。
	c2 := testClient(t, base, true)
	c2.userInfoURL = base + "/bad-json"
	if _, err := c2.UserInfo(context.Background(), &xoauth2.Token{AccessToken: "at-1"}); err == nil ||
		!errx.Is(err, authx.CodeOAuth2Invalid) {
		t.Fatalf("坏 JSON 应报错，实际：%v", err)
	}
	// 非法 URL（请求构造失败）。
	c3 := testClient(t, base, true)
	c3.userInfoURL = "://bad-url"
	if _, err := c3.UserInfo(context.Background(), &xoauth2.Token{AccessToken: "at-1"}); err == nil ||
		!errx.Is(err, authx.CodeOAuth2Invalid) {
		t.Fatalf("非法 URL 应报错，实际：%v", err)
	}
	// 端点不可达（请求执行失败）。
	c4 := testClient(t, base, true)
	c4.userInfoURL = "http://127.0.0.1:1/userinfo"
	if _, err := c4.UserInfo(context.Background(), &xoauth2.Token{AccessToken: "at-1"}); err == nil ||
		!errx.Is(err, authx.CodeOAuth2Invalid) {
		t.Fatalf("连接失败应报错，实际：%v", err)
	}
	// 响应体超限。
	c5 := testClient(t, base, true)
	c5.userInfoURL = base + "/huge"
	if _, err := c5.UserInfo(context.Background(), &xoauth2.Token{AccessToken: "at-1"}); err == nil ||
		!errx.Is(err, authx.CodeOAuth2Invalid) {
		t.Fatalf("超大响应应报错，实际：%v", err)
	}
	// 响应读取失败（Content-Length 与实际不符）。
	c6 := testClient(t, base, true)
	c6.userInfoURL = base + "/truncated"
	if _, err := c6.UserInfo(context.Background(), &xoauth2.Token{AccessToken: "at-1"}); err == nil ||
		!errx.Is(err, authx.CodeOAuth2Invalid) {
		t.Fatalf("读取失败应报错，实际：%v", err)
	}
}

// TestOAuthClient 覆盖携带令牌的标准库客户端。
func TestOAuthClient(t *testing.T) {
	base, srv := mockProvider(t)
	defer srv.Close()
	c := testClient(t, base, false)
	hc := c.Client(context.Background(), &xoauth2.Token{AccessToken: "at-1"})
	resp, err := hc.Get(base + "/userinfo")
	testx.RequireNoError(t, err)

	defer resp.Body.Close()
	testx.RequireEqual(t, resp.StatusCode, http.StatusOK)

}
