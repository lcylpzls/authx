// Package authx 提供工业级认证与授权组件，与 errx / logx / webx 深度集成。
package authx

import "github.com/lcylpzls/errx"

// 错误码统一以 authx_ 为前缀，语义与 HTTP 状态码对齐。
const (
	// CodePasswordHashInvalid 密码哈希格式无效或损坏。
	CodePasswordHashInvalid errx.Code = "authx_password_hash_invalid"
	// CodePasswordMismatch 明文与哈希不匹配（未认证）。
	CodePasswordMismatch errx.Code = "authx_password_mismatch"
	// CodePasswordTooLong 明文密码超过长度上限。
	CodePasswordTooLong errx.Code = "authx_password_too_long"
	// CodePasswordTooShort 明文密码低于长度下限。
	CodePasswordTooShort errx.Code = "authx_password_too_short"
	// CodePasswordConfigInvalid 哈希参数非法。
	CodePasswordConfigInvalid errx.Code = "authx_password_config_invalid"
	// CodePasswordInternal 哈希/校验过程内部失败（随机盐生成等）。
	CodePasswordInternal errx.Code = "authx_password_internal"
)

// 预定义错误值，可用 errx.Is 判断。
var (
	// ErrPasswordHashInvalid 密码哈希格式无效。
	ErrPasswordHashInvalid = errx.New(errx.KindInvalid, CodePasswordHashInvalid, "密码哈希格式无效")
	// ErrPasswordMismatch 明文与哈希不匹配。
	ErrPasswordMismatch = errx.New(errx.KindUnauthorized, CodePasswordMismatch, "密码不匹配")
	// ErrPasswordTooLong 明文密码超过长度上限。
	ErrPasswordTooLong = errx.New(errx.KindInvalid, CodePasswordTooLong, "明文密码长度超过上限")
	// ErrPasswordTooShort 明文密码低于长度下限。
	ErrPasswordTooShort = errx.New(errx.KindInvalid, CodePasswordTooShort, "明文密码长度低于下限")
)
