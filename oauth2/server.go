// Package oauth2 提供 OAuth2/OIDC 客户端与服务端。
package oauth2

import (
	"net/http"

	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	oauth2server "github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/errx"
)

// ServerConfig 授权服务配置。
type ServerConfig struct {
	// ClientID 内置客户端 ID。
	ClientID string
	// ClientSecret 内置客户端密钥（公开客户端可为空）。
	ClientSecret string
	// RedirectURL 内置客户端允许的回调地址。
	RedirectURL string
}

// ServerOption 授权服务配置项。
type ServerOption func(*Server) error

// WithClientBasicAuth 启用 token 端点的客户端 Basic 认证（RFC 6749 推荐）。
// 默认使用表单认证（ClientFormHandler）。
func WithClientBasicAuth() ServerOption {
	return func(s *Server) error {
		s.inner.SetClientInfoHandler(oauth2server.ClientBasicHandler)
		return nil
	}
}

// Server OAuth2 授权服务（授权码 + PKCE + 刷新令牌）。
type Server struct {
	inner       *oauth2server.Server
	contextAuth bool // 是否使用请求上下文解析登录态（预检查未登录）
}

// NewServer 构造授权服务，内置内存客户端与令牌存储。
func NewServer(cfg ServerConfig, opts ...ServerOption) (*Server, error) {
	if cfg.ClientID == "" || cfg.RedirectURL == "" {
		return nil, errx.New(errx.KindInvalid, authx.CodeOAuth2ConfigInvalid, "服务端配置不完整（ClientID/RedirectURL 必填）")
	}
	manager := manage.NewDefaultManager()
	manager.MustTokenStorage(store.NewMemoryTokenStore())
	clientStore := store.NewClientStore()
	clientStore.Set(cfg.ClientID, &models.Client{
		ID:     cfg.ClientID,
		Secret: cfg.ClientSecret,
		Domain: cfg.RedirectURL,
	})
	manager.MapClientStorage(clientStore)

	srv := oauth2server.NewDefaultServer(manager)
	srv.SetAllowGetAccessRequest(true)
	srv.SetClientInfoHandler(oauth2server.ClientFormHandler)
	s := &Server{inner: srv}
	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// SetUserAuthorizationHandler 设置当前登录用户解析器：
// 从请求中（如 webx 会话中间件注入的上下文）解析用户 ID，返回空表示未登录。
func (s *Server) SetUserAuthorizationHandler(fn func(r *http.Request) (string, error)) {
	s.contextAuth = false
	s.inner.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (string, error) {
		return fn(r)
	})
}

// AuthorizeHandler 返回 /authorize 端点处理器。
func (s *Server) AuthorizeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.contextAuth {
			if _, ok := UserIDFromContext(r.Context()); !ok {
				writeUnauthorized(w, "用户未登录")
				return
			}
		}
		// 库内错误已按 OAuth2 规范写响应（授权重定向 error=...），无需二次处理。
		_ = s.inner.HandleAuthorizeRequest(w, r)
	})
}

// TokenHandler 返回 /token 端点处理器。
func (s *Server) TokenHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 库内错误已写 JSON 错误响应（如 invalid_grant），无需二次处理。
		_ = s.inner.HandleTokenRequest(w, r)
	})
}

// writeUnauthorized 输出未登录 JSON 响应。
func writeUnauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"unauthorized","error_description":"` + msg + `"}`))
}
