// Package oauth2 提供 OAuth2/OIDC 客户端与服务端。
package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/errx"
	xoauth2 "golang.org/x/oauth2"
)

// ProviderConfig 第三方登录提供方配置。
type ProviderConfig struct {
	// ClientID 提供方分配的客户端 ID。
	ClientID string
	// ClientSecret 提供方分配的客户端密钥（公开客户端可为空）。
	ClientSecret string
	// AuthURL 授权端点。
	AuthURL string
	// TokenURL 令牌端点。
	TokenURL string
	// UserInfoURL 用户信息端点（可选，留空则 UserInfo 不可用）。
	UserInfoURL string
	// RedirectURL 回调地址。
	RedirectURL string
	// Scopes 申请的授权范围。
	Scopes []string
}

// Client OAuth2 客户端（授权码 + PKCE）。
type Client struct {
	config      *xoauth2.Config
	userInfoURL string
	httpClient  *http.Client
}

// NewClient 构造 OAuth2 客户端。
func NewClient(cfg ProviderConfig) (*Client, error) {
	if cfg.ClientID == "" || cfg.AuthURL == "" || cfg.TokenURL == "" || cfg.RedirectURL == "" {
		return nil, errx.New(errx.KindInvalid, authx.CodeOAuth2ConfigInvalid, "客户端配置不完整（ClientID/AuthURL/TokenURL/RedirectURL 必填）")
	}
	return &Client{
		config: &xoauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint: xoauth2.Endpoint{
				AuthURL:  cfg.AuthURL,
				TokenURL: cfg.TokenURL,
			},
			RedirectURL: cfg.RedirectURL,
			Scopes:      append([]string(nil), cfg.Scopes...),
		},
		userInfoURL: cfg.UserInfoURL,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// AuthCodeURL 生成授权码 URL（无 PKCE）。
func (c *Client) AuthCodeURL(state string) string {
	return c.config.AuthCodeURL(state)
}

// AuthCodeURLWithPKCE 生成带 PKCE（S256）的授权码 URL，返回 URL 与 verifier。
// 调用方必须保存 verifier，并在 Exchange 时传回。
func (c *Client) AuthCodeURLWithPKCE(state string) (string, string) {
	verifier := xoauth2.GenerateVerifier()
	return c.config.AuthCodeURL(state, xoauth2.S256ChallengeOption(verifier)), verifier
}

// Exchange 用授权码交换令牌；verifier 非空时启用 PKCE 校验。
func (c *Client) Exchange(ctx context.Context, code, verifier string) (*xoauth2.Token, error) {
	var opts []xoauth2.AuthCodeOption
	if verifier != "" {
		opts = append(opts, xoauth2.VerifierOption(verifier))
	}
	tok, err := c.config.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, errx.Wrap(err, errx.KindUnauthorized, authx.CodeOAuth2Invalid, "OAuth2 令牌交换失败")
	}
	return tok, nil
}

// UserInfo 拉取用户信息（需要配置 UserInfoURL）。
func (c *Client) UserInfo(ctx context.Context, tok *xoauth2.Token) (map[string]any, error) {
	if c.userInfoURL == "" {
		return nil, errx.New(errx.KindInvalid, authx.CodeOAuth2ConfigInvalid, "未配置用户信息端点")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.userInfoURL, nil)
	if err != nil {
		return nil, errx.Wrap(err, errx.KindInvalid, authx.CodeOAuth2Invalid, "用户信息请求构造失败")
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errx.Wrap(err, errx.KindUnavailable, authx.CodeOAuth2Invalid, "用户信息请求失败")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errx.New(errx.KindUnavailable, authx.CodeOAuth2Invalid, "用户信息端点返回非 200")
	}
	var info map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, errx.Wrap(err, errx.KindInvalid, authx.CodeOAuth2Invalid, "用户信息解析失败")
	}
	return info, nil
}

// Client 返回携带令牌的标准库 HTTP 客户端。
func (c *Client) Client(ctx context.Context, tok *xoauth2.Token) *http.Client {
	return c.config.Client(ctx, tok)
}
