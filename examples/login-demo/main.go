// Package main 演示 authx 全套组件在 webx 服务中的组合用法（登录演示）。
package main

import (
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/authx/audit"
	"github.com/lcylpzls/authx/mfa"
	"github.com/lcylpzls/authx/middleware"
	"github.com/lcylpzls/authx/oauth2"
	"github.com/lcylpzls/authx/password"
	"github.com/lcylpzls/authx/rbac"
	"github.com/lcylpzls/authx/security"
	"github.com/lcylpzls/authx/session"
	"github.com/lcylpzls/authx/token"
	"github.com/lcylpzls/logx"
	"github.com/lcylpzls/webx/v2"
)

const (
	csrfCookie = "csrf"
	csrfHeader = "X-CSRF-Token"
	sessCookie = "sid"
)

// user 演示用户。
type user struct {
	ID           string
	Username     string
	PasswordHash string
	Roles        []string
	MFASecret    string
}

// userStore 内存用户仓库（演示用，生产应接数据库）。
type userStore struct {
	mu     sync.RWMutex
	byID   map[string]*user
	byName map[string]*user
}

// newUserStore 构造空用户仓库。
func newUserStore() *userStore {
	return &userStore{byID: map[string]*user{}, byName: map[string]*user{}}
}

// create 创建用户；用户名已存在返回错误。
func (s *userStore) create(username, hash string, roles ...string) (*user, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byName[username]; ok {
		return nil, fmt.Errorf("用户名已存在")
	}
	u := &user{ID: fmt.Sprintf("u-%d", len(s.byID)+1), Username: username,
		PasswordHash: hash, Roles: roles}
	s.byID[u.ID] = u
	s.byName[username] = u
	return u, nil
}

// byUsername 按用户名读取用户。
func (s *userStore) byUsername(name string) (*user, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byName[name]
	return u, ok
}

// get 按 ID 读取用户。
func (s *userStore) get(id string) (*user, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byID[id]
	return u, ok
}

// appDeps 演示应用依赖。
type appDeps struct {
	users     *userStore
	auditor   *audit.AsyncAuditor
	guard     *security.LoginGuard
	signer    *token.Signer
	rb        *rbac.RBAC
	sessStore session.Store
	cleanup   *authx.CleanupHandle
}

// Close 释放后台资源。
func (d *appDeps) Close() {
	d.cleanup.Stop()
	d.auditor.Stop()
}

// registerRequest 注册请求体。
type registerRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// loginRequest 登录请求体。
type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// mfaRequest MFA 校验请求体。
type mfaRequest struct {
	Code string `json:"code"`
}

// newApp 装配完整登录演示应用，返回路由与依赖。
func newApp() ([]webx.Route, *appDeps, error) {
	logger, err := logx.NewBuilder().EnableWriter(io.Discard, logx.InfoLevel).Build()
	if err != nil {
		return nil, nil, err
	}
	auditor, err := audit.NewAsyncAuditor(logger, 256)
	if err != nil {
		return nil, nil, err
	}
	auditor.AddHook(func(e audit.Event) {
		// 演示持久化钩子：生产可在此批量落库。
	})
	guard, err := security.NewLoginGuard(5, 5*time.Minute)
	if err != nil {
		return nil, nil, err
	}
	signer, err := token.NewHS256([]byte("0123456789abcdef0123456789abcdef"),
		token.WithIssuer("login-demo"), token.WithTTL(15*time.Minute))
	if err != nil {
		return nil, nil, err
	}
	rb := rbac.New()
	if err := rb.AddRole("user", "profile:read"); err != nil {
		return nil, nil, err
	}
	if err := rb.AddRole("admin", "profile:read", "admin:all"); err != nil {
		return nil, nil, err
	}
	if err := rb.Inherit("admin", "user"); err != nil {
		return nil, nil, err
	}
	sessStore := session.NewMemoryStore(nil)
	users := newUserStore()
	seedHash, err := password.HashWithStrength("admin123!",
		authx.DefaultPasswordConfig(),
		password.StrengthConfig{RequireDigit: true, RequireSymbol: true})
	if err != nil {
		return nil, nil, err
	}
	admin, err := users.create("admin", seedHash, "admin")
	if err != nil {
		return nil, nil, err
	}
	secret, err := mfa.GenerateSecret()
	if err != nil {
		return nil, nil, err
	}
	admin.MFASecret = secret

	deps := &appDeps{
		users:     users,
		auditor:   auditor,
		guard:     guard,
		signer:    signer,
		rb:        rb,
		sessStore: sessStore,
		cleanup:   sessStore.StartCleanup(10 * time.Minute),
	}

	// 会话与 CSRF 中间件。
	sessMW := middleware.Session(sessStore, sessCookie,
		middleware.WithSessionSecure(false),
		middleware.WithSessionSigningKey([]byte("0123456789abcdef")))
	csrfMW := middleware.CSRFProtect(csrfCookie, csrfHeader,
		middleware.WithCSRFSecure(false),
		middleware.WithCSRFAllowedOrigins("http://localhost:8080"))

	routes := []webx.Route{
		{Method: http.MethodGet, Path: "/api/csrf", Handler: func(c *webx.Context) {
			c.Success("就绪", nil)
		}, Middleware: []webx.HandlerFunc{sessMW, csrfMW}},
		{Method: http.MethodPost, Path: "/api/register",
			Handler: registerHandler(deps), Middleware: []webx.HandlerFunc{sessMW, csrfMW}},
		{Method: http.MethodPost, Path: "/api/login",
			Handler: loginHandler(deps), Middleware: []webx.HandlerFunc{sessMW, csrfMW}},
		{Method: http.MethodGet, Path: "/api/me",
			Handler: meHandler(deps), Middleware: []webx.HandlerFunc{middleware.Auth(signer)}},
		{Method: http.MethodGet, Path: "/api/admin",
			Handler: adminHandler(deps),
			Middleware: []webx.HandlerFunc{
				middleware.Auth(signer),
				middleware.RequirePermission(rb, "admin:all"),
			}},
		{Method: http.MethodGet, Path: "/api/mfa/setup",
			Handler: mfaSetupHandler(deps), Middleware: []webx.HandlerFunc{sessMW}},
		{Method: http.MethodPost, Path: "/api/mfa/verify",
			Handler: mfaVerifyHandler(deps), Middleware: []webx.HandlerFunc{sessMW}},
	}

	// OAuth2 服务端（webx 适配）。
	oauthSrv, err := oauth2.NewServer(oauth2.ServerConfig{
		ClientID:     "web",
		ClientSecret: "secret",
		RedirectURL:  "http://localhost:8080/cb",
	})
	if err != nil {
		return nil, nil, err
	}
	oauthSrv.SetUserAuthorizationHandlerFromContext()
	routes = append(routes,
		webx.Route{Method: http.MethodGet, Path: "/oauth/authorize",
			Handler: oauthSrv.AuthorizeWebxHandler(), Middleware: []webx.HandlerFunc{sessMW}},
		webx.Route{Method: http.MethodPost, Path: "/oauth/token",
			Handler: oauthSrv.TokenWebxHandler()},
	)
	return routes, deps, nil
}

// registerHandler 注册：强度校验 + Argon2id 哈希 + 审计。
func registerHandler(d *appDeps) webx.HandlerFunc {
	return func(c *webx.Context) {
		var req registerRequest
		if err := c.BindJSON(&req); err != nil || req.Username == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, "请求参数非法", nil)
			return
		}
		hash, err := password.HashWithStrength(req.Password, authx.DefaultPasswordConfig(),
			password.StrengthConfig{RequireDigit: true, RequireSymbol: true})
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, err.Error(), nil)
			return
		}
		u, err := d.users.create(req.Username, hash, "user")
		if err != nil {
			c.AbortWithStatusJSON(http.StatusConflict, err.Error(), nil)
			return
		}
		d.auditor.Record(audit.Event{Action: "user.register", Subject: u.ID, Result: audit.ResultSuccess})
		c.Success("注册成功", map[string]string{"id": u.ID})
	}
}

// loginHandler 登录：防爆破 + 密码校验 + JWT 签发 + 会话轮换 + 审计。
func loginHandler(d *appDeps) webx.HandlerFunc {
	return func(c *webx.Context) {
		var req loginRequest
		if err := c.BindJSON(&req); err != nil || req.Username == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, "请求参数非法", nil)
			return
		}
		if d.guard.IsLocked(req.Username) {
			d.auditor.Record(audit.Event{Action: "user.login", Subject: req.Username,
				Result: audit.ResultFailure, Detail: "账号已锁定"})
			c.AbortWithStatusJSON(http.StatusTooManyRequests, "账号已锁定，请稍后重试", nil)
			return
		}
		u, ok := d.users.byUsername(req.Username)
		if !ok {
			d.guard.RecordFailure(req.Username)
			c.AbortWithStatusJSON(http.StatusUnauthorized, "用户名或密码错误", nil)
			return
		}
		valid, err := password.Verify(u.PasswordHash, req.Password)
		if err != nil || !valid {
			d.guard.RecordFailure(req.Username)
			d.auditor.Record(audit.Event{Action: "user.login", Subject: u.ID,
				Result: audit.ResultFailure, Detail: "密码错误"})
			c.AbortWithStatusJSON(http.StatusUnauthorized, "用户名或密码错误", nil)
			return
		}
		d.guard.Reset(req.Username)
		// 登录成功后轮换会话，防会话固定。
		if err := middleware.RotateSession(c); err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, err.Error(), nil)
			return
		}
		if sess, ok := middleware.SessionFrom(c); ok {
			sess.Values["uid"] = u.ID
		}
		raw, err := d.signer.Sign(u.ID, token.WithRoles(u.Roles...))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, "令牌签发失败", nil)
			return
		}
		d.auditor.Record(audit.Event{Action: "user.login", Subject: u.ID, Result: audit.ResultSuccess})
		c.Success("登录成功", map[string]string{"access_token": raw, "user_id": u.ID})
	}
}

// meHandler 返回当前登录用户。
func meHandler(d *appDeps) webx.HandlerFunc {
	return func(c *webx.Context) {
		claims, _ := middleware.ClaimsFrom(c)
		c.Success("当前用户", map[string]any{
			"user_id": claims.Subject,
			"roles":   claims.Roles,
		})
	}
}

// adminHandler 仅管理员可访问。
func adminHandler(d *appDeps) webx.HandlerFunc {
	return func(c *webx.Context) {
		c.Success("管理员接口", nil)
	}
}

// mfaSetupHandler 返回当前会话用户的 TOTP 密钥。
func mfaSetupHandler(d *appDeps) webx.HandlerFunc {
	return func(c *webx.Context) {
		sess, ok := middleware.SessionFrom(c)
		if !ok || sess.Values["uid"] == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, "请先登录", nil)
			return
		}
		u, ok := d.users.get(sess.Values["uid"])
		if !ok || u.MFASecret == "" {
			c.AbortWithStatusJSON(http.StatusNotFound, "未配置 MFA", nil)
			return
		}
		c.Success("MFA 配置", map[string]string{"secret": u.MFASecret})
	}
}

// mfaVerifyHandler 校验 TOTP 验证码。
func mfaVerifyHandler(d *appDeps) webx.HandlerFunc {
	return func(c *webx.Context) {
		sess, ok := middleware.SessionFrom(c)
		if !ok || sess.Values["uid"] == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, "请先登录", nil)
			return
		}
		var req mfaRequest
		if err := c.BindJSON(&req); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, "请求参数非法", nil)
			return
		}
		u, ok := d.users.get(sess.Values["uid"])
		if !ok || u.MFASecret == "" {
			c.AbortWithStatusJSON(http.StatusNotFound, "未配置 MFA", nil)
			return
		}
		valid, err := mfa.ValidateCode(u.MFASecret, req.Code, time.Now(), 1)
		if err != nil || !valid {
			c.AbortWithStatusJSON(http.StatusBadRequest, "验证码错误", nil)
			return
		}
		c.Success("MFA 校验通过", nil)
	}
}

// run 组装演示应用并输出路由清单。
func run() error {
	routes, deps, err := newApp()
	if err != nil {
		return err
	}
	defer deps.Close()
	logger, err := logx.NewBuilder().EnableWriter(io.Discard, logx.InfoLevel).Build()
	if err != nil {
		return err
	}
	defer logger.Close()
	s := webx.NewServer(webx.Config{}, logger)
	s.RegisterRoutes(routes)
	fmt.Printf("login-demo 已装配，共 %d 条路由\n", len(routes))
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Println("示例失败：", err)
	}
}
