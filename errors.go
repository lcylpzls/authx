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
	// CodeTokenInvalid 令牌格式非法或载荷非法。
	CodeTokenInvalid errx.Code = "authx_token_invalid"
	// CodeTokenExpired 令牌已过期。
	CodeTokenExpired errx.Code = "authx_token_expired"
	// CodeTokenSignature 令牌签名无效。
	CodeTokenSignature errx.Code = "authx_token_signature"
	// CodeTokenRevoked 令牌已撤销。
	CodeTokenRevoked errx.Code = "authx_token_revoked"
	// CodeTokenConfigInvalid 令牌配置非法（密钥过短、TTL 非正等）。
	CodeTokenConfigInvalid errx.Code = "authx_token_config_invalid"
	// CodeRefreshTokenInvalid 刷新令牌无效或已使用。
	CodeRefreshTokenInvalid errx.Code = "authx_refresh_token_invalid"
	// CodeStoreInvalid 存储参数非法。
	CodeStoreInvalid errx.Code = "authx_store_invalid"
	// CodeForbidden 已认证但无权限（403）。
	CodeForbidden errx.Code = "authx_forbidden"
	// CodeRBACRoleNotFound 角色不存在。
	CodeRBACRoleNotFound errx.Code = "authx_rbac_role_not_found"
	// CodeRBACRoleExists 角色已存在。
	CodeRBACRoleExists errx.Code = "authx_rbac_role_exists"
	// CodeRBACCycle 角色继承形成环。
	CodeRBACCycle errx.Code = "authx_rbac_cycle"
	// CodeRBACInvalid 角色名/权限参数非法。
	CodeRBACInvalid errx.Code = "authx_rbac_invalid"
	// CodeCSRFMismatch CSRF 校验不通过。
	CodeCSRFMismatch errx.Code = "authx_csrf_mismatch"
	// CodeSessionNotFound 会话不存在或已过期。
	CodeSessionNotFound errx.Code = "authx_session_not_found"
	// CodeSessionInvalid 会话参数非法（空 ID、TTL 非正等）。
	CodeSessionInvalid errx.Code = "authx_session_invalid"
	// CodeSessionStoreInvalid 会话存储不可用。
	CodeSessionStoreInvalid errx.Code = "authx_session_store_invalid"
	// CodeMFAInvalid 多因素参数非法（密钥无法解码、验证码格式错误等）。
	CodeMFAInvalid errx.Code = "authx_mfa_invalid"
	// CodeMFAConfigInvalid 多因素配置非法。
	CodeMFAConfigInvalid errx.Code = "authx_mfa_config_invalid"
	// CodeOAuth2Invalid OAuth2 流程失败（令牌交换、授权码等）。
	CodeOAuth2Invalid errx.Code = "authx_oauth2_invalid"
	// CodeOAuth2ConfigInvalid OAuth2 配置非法。
	CodeOAuth2ConfigInvalid errx.Code = "authx_oauth2_config_invalid"
	// CodeSecurityConfigInvalid 安全策略配置非法。
	CodeSecurityConfigInvalid errx.Code = "authx_security_config_invalid"
	// CodeStoreFull 存储容量已满，拒绝继续写入（防内存无限增长）。
	CodeStoreFull errx.Code = "authx_store_full"
	// CodeRBACLimit RBAC 规模超出上限（角色数量或继承深度）。
	CodeRBACLimit errx.Code = "authx_rbac_limit"
	// CodeCSRFGenerationFailed CSRF 令牌生成失败。
	CodeCSRFGenerationFailed errx.Code = "authx_csrf_generation_failed"
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
	// ErrTokenInvalid 令牌格式非法或载荷非法。
	ErrTokenInvalid = errx.New(errx.KindUnauthorized, CodeTokenInvalid, "令牌格式非法")
	// ErrTokenExpired 令牌已过期。
	ErrTokenExpired = errx.New(errx.KindUnauthorized, CodeTokenExpired, "令牌已过期")
	// ErrTokenSignature 令牌签名无效。
	ErrTokenSignature = errx.New(errx.KindUnauthorized, CodeTokenSignature, "令牌签名无效")
	// ErrTokenRevoked 令牌已撤销。
	ErrTokenRevoked = errx.New(errx.KindUnauthorized, CodeTokenRevoked, "令牌已撤销")
	// ErrRefreshTokenInvalid 刷新令牌无效或已使用。
	ErrRefreshTokenInvalid = errx.New(errx.KindUnauthorized, CodeRefreshTokenInvalid, "刷新令牌无效或已使用")
	// ErrForbidden 已认证但无权限。
	ErrForbidden = errx.New(errx.KindForbidden, CodeForbidden, "无权限执行该操作")
	// ErrRoleNotFound 角色不存在。
	ErrRoleNotFound = errx.New(errx.KindInvalid, CodeRBACRoleNotFound, "角色不存在")
	// ErrRoleExists 角色已存在。
	ErrRoleExists = errx.New(errx.KindConflict, CodeRBACRoleExists, "角色已存在")
	// ErrCycle 角色继承形成环。
	ErrCycle = errx.New(errx.KindInvalid, CodeRBACCycle, "角色继承不能形成环")
	// ErrRBACInvalid 角色名/权限参数非法。
	ErrRBACInvalid = errx.New(errx.KindInvalid, CodeRBACInvalid, "角色或权限参数非法")
	// ErrCSRFMismatch CSRF 校验不通过。
	ErrCSRFMismatch = errx.New(errx.KindForbidden, CodeCSRFMismatch, "CSRF 校验失败")
	// ErrSessionNotFound 会话不存在或已过期。
	ErrSessionNotFound = errx.New(errx.KindUnauthorized, CodeSessionNotFound, "会话不存在或已过期")
	// ErrSessionInvalid 会话参数非法。
	ErrSessionInvalid = errx.New(errx.KindInvalid, CodeSessionInvalid, "会话参数非法")
	// ErrSessionStoreInvalid 会话存储不可用。
	ErrSessionStoreInvalid = errx.New(errx.KindUnavailable, CodeSessionStoreInvalid, "会话存储不可用")
	// ErrMFAInvalid 多因素参数非法。
	ErrMFAInvalid = errx.New(errx.KindInvalid, CodeMFAInvalid, "多因素参数非法")
	// ErrMFAConfigInvalid 多因素配置非法。
	ErrMFAConfigInvalid = errx.New(errx.KindInvalid, CodeMFAConfigInvalid, "多因素配置非法")
	// ErrOAuth2Invalid OAuth2 流程失败。
	ErrOAuth2Invalid = errx.New(errx.KindUnauthorized, CodeOAuth2Invalid, "OAuth2 流程失败")
	// ErrOAuth2ConfigInvalid OAuth2 配置非法。
	ErrOAuth2ConfigInvalid = errx.New(errx.KindInvalid, CodeOAuth2ConfigInvalid, "OAuth2 配置非法")
	// ErrSecurityConfigInvalid 安全策略配置非法。
	ErrSecurityConfigInvalid = errx.New(errx.KindInvalid, CodeSecurityConfigInvalid, "安全策略配置非法")
	// ErrStoreFull 存储容量已满。
	ErrStoreFull = errx.New(errx.KindUnavailable, CodeStoreFull, "存储容量已满")
	// ErrRBACLimit RBAC 规模超出上限。
	ErrRBACLimit = errx.New(errx.KindInvalid, CodeRBACLimit, "RBAC 规模超出上限")
	// ErrCSRFGenerationFailed CSRF 令牌生成失败。
	ErrCSRFGenerationFailed = errx.New(errx.KindUnavailable, CodeCSRFGenerationFailed, "CSRF 令牌生成失败")
)
