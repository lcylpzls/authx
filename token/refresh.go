package token

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/errx"
)

const refreshTokenBytes = 32

// IssueRefreshToken 生成刷新令牌并存储其哈希，返回明文令牌。
func IssueRefreshToken(ctx context.Context, store RefreshStore, ttl time.Duration, opts ...TraceOption) (token string, err error) {
	ctx, end := startTrace(ctx, "authx.refresh.issue", "issue", applyOptions(opts))
	defer func() { end(err) }()
	if store == nil {
		return "", errx.New(errx.KindInvalid, authx.CodeRefreshTokenInvalid, "刷新令牌存储不能为空")
	}
	raw := make([]byte, refreshTokenBytes)
	if _, err := randRead(raw); err != nil {
		return "", errx.Wrap(err, errx.KindUnavailable, authx.CodeRefreshTokenInvalid, "刷新令牌生成失败")
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	if err := store.Save(ctx, HashRefreshToken(token), ttl); err != nil {
		return "", errx.Wrap(err, errx.KindUnavailable, authx.CodeRefreshTokenInvalid, "刷新令牌存储失败")
	}
	return token, nil
}

// ValidateRefreshToken 校验刷新令牌是否有效（不消费，单次使用由业务调用 Delete）。
func ValidateRefreshToken(ctx context.Context, store RefreshStore, raw string, opts ...TraceOption) (ok bool, err error) {
	ctx, end := startTrace(ctx, "authx.refresh.validate", "validate", applyOptions(opts))
	defer func() { end(err) }()
	if store == nil || raw == "" {
		return false, errx.New(errx.KindInvalid, authx.CodeRefreshTokenInvalid, "刷新令牌或存储不能为空")
	}
	ok, err = store.Validate(ctx, HashRefreshToken(raw))
	if err != nil {
		return false, errx.Wrap(err, errx.KindUnavailable, authx.CodeRefreshTokenInvalid, "刷新令牌查询失败")
	}
	return ok, nil
}

// ConsumeRefreshToken 消费刷新令牌（轮换时调用，保证单次使用）。
func ConsumeRefreshToken(ctx context.Context, store RefreshStore, raw string, opts ...TraceOption) (err error) {
	ctx, end := startTrace(ctx, "authx.refresh.consume", "consume", applyOptions(opts))
	defer func() { end(err) }()
	if store == nil || raw == "" {
		return errx.New(errx.KindInvalid, authx.CodeRefreshTokenInvalid, "刷新令牌或存储不能为空")
	}
	if err := store.Delete(ctx, HashRefreshToken(raw)); err != nil {
		return errx.Wrap(err, errx.KindUnavailable, authx.CodeRefreshTokenInvalid, "刷新令牌删除失败")
	}
	return nil
}

// RotateRefreshToken 轮换刷新令牌：校验旧令牌有效后删除旧哈希并签发新令牌。
// 用于刷新流程，保证单次使用（旧令牌立即失效）。
func RotateRefreshToken(ctx context.Context, store RefreshStore, oldRaw string, ttl time.Duration, opts ...TraceOption) (token string, err error) {
	ctx, end := startTrace(ctx, "authx.refresh.rotate", "rotate", applyOptions(opts))
	defer func() { end(err) }()
	if store == nil || oldRaw == "" {
		return "", errx.New(errx.KindInvalid, authx.CodeRefreshTokenInvalid, "刷新令牌或存储不能为空")
	}
	ok, err := store.Validate(ctx, HashRefreshToken(oldRaw))
	if err != nil {
		return "", errx.Wrap(err, errx.KindUnavailable, authx.CodeRefreshTokenInvalid, "刷新令牌查询失败")
	}
	if !ok {
		return "", authx.ErrRefreshTokenInvalid
	}
	if err := store.Delete(ctx, HashRefreshToken(oldRaw)); err != nil {
		return "", errx.Wrap(err, errx.KindUnavailable, authx.CodeRefreshTokenInvalid, "刷新令牌删除失败")
	}
	return IssueRefreshToken(ctx, store, ttl)
}

// startTrace 开始令牌操作链路（无钩子时 no-op）。
func startTrace(ctx context.Context, name, op string, c *traceConfig) (context.Context, func(error)) {
	if c.traceHook == nil && c.eventHook == nil {
		return ctx, func(error) {}
	}
	traceEnd := func(error) {}
	if c.traceHook != nil {
		ctx, traceEnd = c.traceHook.Start(ctx, name, authx.TraceAttr{Key: "authx.operation", Value: op})
	}
	return ctx, func(err error) {
		traceEnd(err)
		if c.eventHook != nil {
			c.eventHook.OnAuthEvent(ctx, authx.AuthEvent{Action: op, Err: err})
		}
	}
}

// HashRefreshToken 计算刷新令牌哈希（存储与查询使用，明文不落库）。
func HashRefreshToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
