// Package main 展示 authx 全套组件的组合用法（编译示例，非可运行服务）。
package main

import (
	"context"
	"fmt"
	"io"
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
	"github.com/lcylpzls/webx"
)

func main() {
	if err := run(); err != nil {
		fmt.Println("示例失败：", err)
	}
}

// run 演示 authx 全套组件的组合用法。
func run() error {
	// 日志与审计。
	logger, err := logx.NewBuilder().EnableWriter(io.Discard, logx.InfoLevel).Build()
	if err != nil {
		return err
	}
	auditor := audit.New(logger)
	auditor.AddHook(func(e audit.Event) { fmt.Printf("审计落库：%s %s\n", e.Action, e.Subject) })

	// 密码哈希。
	hash, err := password.Hash("password123", authx.DefaultPasswordConfig())
	if err != nil {
		return err
	}
	ok, err := password.Verify(hash, "password123")
	if err != nil {
		return err
	}
	fmt.Println("密码校验：", ok)

	// 令牌。
	signer, err := token.NewHS256([]byte("0123456789abcdef0123456789abcdef"),
		token.WithIssuer("myapp"), token.WithTTL(15*time.Minute))
	if err != nil {
		return err
	}
	access, err := signer.Sign("u-1001", token.WithRoles("admin"))
	if err != nil {
		return err
	}
	claims, err := signer.Parse(access)
	if err != nil {
		return err
	}
	fmt.Println("令牌主体：", claims.Subject)

	// 刷新令牌。
	refreshStore := token.NewMemoryRefreshStore(nil)
	refresh, err := token.IssueRefreshToken(context.Background(), refreshStore, 720*time.Hour)
	if err != nil {
		return err
	}
	fmt.Println("刷新令牌已签发：", refresh != "")

	// RBAC 与中间件。
	rb := rbac.New()
	if err := rb.AddRole("admin", "order:read", "order:write"); err != nil {
		return err
	}
	authMW := middleware.Auth(signer)
	permMW := middleware.RequirePermission(rb, "order:read")
	_ = authMW
	_ = permMW

	// 会话。
	sessStore := session.NewMemoryStore(nil)
	sessMW := middleware.Session(sessStore, "sid", middleware.WithSessionTTL(24*time.Hour))
	_ = sessMW

	// 多因素。
	secret, err := mfa.GenerateSecret()
	if err != nil {
		return err
	}
	code, err := mfa.GenerateCode(secret, time.Now())
	if err != nil {
		return err
	}
	valid, err := mfa.ValidateCode(secret, code, time.Now(), 1)
	if err != nil {
		return err
	}
	fmt.Println("TOTP 校验：", valid)

	// 登录防爆破。
	guard, err := security.NewLoginGuard(5, time.Minute)
	if err != nil {
		return err
	}
	guard.RecordFailure("u-1001")
	fmt.Println("锁定状态：", guard.IsLocked("u-1001"))

	// OAuth2 服务端（webx 适配）。
	oauthSrv, err := oauth2.NewServer(oauth2.ServerConfig{
		ClientID:     "web",
		ClientSecret: "secret",
		RedirectURL:  "http://localhost:8080/cb",
	})
	if err != nil {
		return err
	}
	oauthSrv.SetUserAuthorizationHandlerFromContext()
	_ = oauthSrv.AuthorizeWebxHandler()
	_ = oauthSrv.TokenWebxHandler()

	// webx 服务装配（示意）。
	s := webx.NewServer(webx.Config{}, logger)
	_ = s
	return nil
}
