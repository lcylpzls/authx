// Package authx 提供工业级认证与授权组件，与 errx / logx / webx 深度集成。
package authx

import "github.com/lcylpzls/errx"

// registerCodes 在错误值初始化前完成注册，保证 NewCode 自动分类生效
// （包级变量初始化先于 init 执行，故不用 init 注册）。
var _ = registerCodes()

func registerCodes() bool {
	errx.RegisterCode(CodePasswordHashInvalid, "密码哈希格式无效或损坏")
	errx.RegisterCodeKind(CodePasswordHashInvalid, errx.KindInvalid)
	errx.RegisterCode(CodePasswordMismatch, "明文与哈希不匹配")
	errx.RegisterCodeKind(CodePasswordMismatch, errx.KindUnauthorized)
	errx.RegisterCode(CodePasswordTooLong, "明文密码超过长度上限")
	errx.RegisterCodeKind(CodePasswordTooLong, errx.KindInvalid)
	errx.RegisterCode(CodePasswordTooShort, "明文密码低于长度下限")
	errx.RegisterCodeKind(CodePasswordTooShort, errx.KindInvalid)
	errx.RegisterCode(CodePasswordConfigInvalid, "哈希参数非法")
	errx.RegisterCodeKind(CodePasswordConfigInvalid, errx.KindInvalid)
	errx.RegisterCode(CodePasswordInternal, "哈希/校验过程内部失败")
	errx.RegisterCodeKind(CodePasswordInternal, errx.KindUnavailable)
	errx.RegisterCode(CodePasswordTooWeak, "密码强度不足")
	errx.RegisterCodeKind(CodePasswordTooWeak, errx.KindInvalid)
	errx.RegisterCode(CodeTokenInvalid, "令牌格式非法或载荷非法")
	errx.RegisterCodeKind(CodeTokenInvalid, errx.KindUnauthorized)
	errx.RegisterCode(CodeTokenExpired, "令牌已过期")
	errx.RegisterCodeKind(CodeTokenExpired, errx.KindUnauthorized)
	errx.RegisterCode(CodeTokenSignature, "令牌签名无效")
	errx.RegisterCodeKind(CodeTokenSignature, errx.KindUnauthorized)
	errx.RegisterCode(CodeTokenRevoked, "令牌已撤销")
	errx.RegisterCodeKind(CodeTokenRevoked, errx.KindUnauthorized)
	errx.RegisterCode(CodeTokenMissing, "缺少令牌")
	errx.RegisterCodeKind(CodeTokenMissing, errx.KindUnauthorized)
	errx.RegisterCode(CodeTokenConfigInvalid, "令牌配置非法")
	errx.RegisterCodeKind(CodeTokenConfigInvalid, errx.KindInvalid)
	errx.RegisterCode(CodeRefreshTokenInvalid, "刷新令牌无效")
	errx.RegisterCodeKind(CodeRefreshTokenInvalid, errx.KindUnauthorized)
	errx.RegisterCode(CodeStoreInvalid, "存储读写失败")
	errx.RegisterCodeKind(CodeStoreInvalid, errx.KindUnavailable)
	errx.RegisterCode(CodeStoreFull, "存储容量已满")
	errx.RegisterCodeKind(CodeStoreFull, errx.KindUnavailable)
	errx.RegisterCode(CodeForbidden, "无权限")
	errx.RegisterCodeKind(CodeForbidden, errx.KindForbidden)
	errx.RegisterCode(CodeRBACRoleNotFound, "角色不存在")
	errx.RegisterCodeKind(CodeRBACRoleNotFound, errx.KindInvalid)
	errx.RegisterCode(CodeRBACRoleExists, "角色已存在")
	errx.RegisterCodeKind(CodeRBACRoleExists, errx.KindConflict)
	errx.RegisterCode(CodeRBACCycle, "角色继承环")
	errx.RegisterCodeKind(CodeRBACCycle, errx.KindInvalid)
	errx.RegisterCode(CodeRBACInvalid, "RBAC 参数非法")
	errx.RegisterCodeKind(CodeRBACInvalid, errx.KindInvalid)
	errx.RegisterCode(CodeRBACLimit, "角色/权限数量超限")
	errx.RegisterCodeKind(CodeRBACLimit, errx.KindInvalid)
	errx.RegisterCode(CodeCSRFMismatch, "CSRF 校验不匹配")
	errx.RegisterCodeKind(CodeCSRFMismatch, errx.KindForbidden)
	errx.RegisterCode(CodeCSRFGenerationFailed, "CSRF 令牌生成失败")
	errx.RegisterCodeKind(CodeCSRFGenerationFailed, errx.KindUnavailable)
	errx.RegisterCode(CodeSessionNotFound, "会话不存在")
	errx.RegisterCodeKind(CodeSessionNotFound, errx.KindUnauthorized)
	errx.RegisterCode(CodeSessionInvalid, "会话无效")
	errx.RegisterCodeKind(CodeSessionInvalid, errx.KindInvalid)
	errx.RegisterCode(CodeSessionStoreInvalid, "会话存储失败")
	errx.RegisterCodeKind(CodeSessionStoreInvalid, errx.KindUnavailable)
	errx.RegisterCode(CodeMFAInvalid, "MFA 校验失败")
	errx.RegisterCodeKind(CodeMFAInvalid, errx.KindInvalid)
	errx.RegisterCode(CodeMFAConfigInvalid, "MFA 配置非法")
	errx.RegisterCodeKind(CodeMFAConfigInvalid, errx.KindInvalid)
	errx.RegisterCode(CodeOAuth2Invalid, "OAuth2 参数非法")
	errx.RegisterCodeKind(CodeOAuth2Invalid, errx.KindUnauthorized)
	errx.RegisterCode(CodeOAuth2ConfigInvalid, "OAuth2 配置非法")
	errx.RegisterCodeKind(CodeOAuth2ConfigInvalid, errx.KindInvalid)
	errx.RegisterCode(CodeSecurityConfigInvalid, "安全配置非法")
	errx.RegisterCodeKind(CodeSecurityConfigInvalid, errx.KindInvalid)
	errx.RegisterCode(CodeAuditQueueFull, "审计队列已满")
	errx.RegisterCodeKind(CodeAuditQueueFull, errx.KindRateLimited)
	return true
}

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
	// CodePasswordTooWeak 明文密码不满足强度策略。
	CodePasswordTooWeak errx.Code = "authx_password_too_weak"
	// CodeTokenMissing 请求未携带访问令牌（401）。
	CodeTokenMissing errx.Code = "authx_token_missing"
	// CodeAuditQueueFull 异步审计队列已满，事件被丢弃。
	CodeAuditQueueFull errx.Code = "authx_audit_queue_full"
)

// 预定义错误值，可用 errx.Is 判断。
var (
	// ErrPasswordHashInvalid 密码哈希格式无效。
	ErrPasswordHashInvalid = errx.NewCode(CodePasswordHashInvalid, "密码哈希格式无效")
	// ErrPasswordMismatch 明文与哈希不匹配。
	ErrPasswordMismatch = errx.NewCode(CodePasswordMismatch, "密码不匹配")
	// ErrPasswordTooLong 明文密码超过长度上限。
	ErrPasswordTooLong = errx.NewCode(CodePasswordTooLong, "明文密码长度超过上限")
	// ErrPasswordTooShort 明文密码低于长度下限。
	ErrPasswordTooShort = errx.NewCode(CodePasswordTooShort, "明文密码长度低于下限")
	// ErrTokenInvalid 令牌格式非法或载荷非法。
	ErrTokenInvalid = errx.NewCode(CodeTokenInvalid, "令牌格式非法")
	// ErrTokenExpired 令牌已过期。
	ErrTokenExpired = errx.NewCode(CodeTokenExpired, "令牌已过期")
	// ErrTokenSignature 令牌签名无效。
	ErrTokenSignature = errx.NewCode(CodeTokenSignature, "令牌签名无效")
	// ErrTokenRevoked 令牌已撤销。
	ErrTokenRevoked = errx.NewCode(CodeTokenRevoked, "令牌已撤销")
	// ErrRefreshTokenInvalid 刷新令牌无效或已使用。
	ErrRefreshTokenInvalid = errx.NewCode(CodeRefreshTokenInvalid, "刷新令牌无效或已使用")
	// ErrForbidden 已认证但无权限。
	ErrForbidden = errx.NewCode(CodeForbidden, "无权限执行该操作")
	// ErrRoleNotFound 角色不存在。
	ErrRoleNotFound = errx.NewCode(CodeRBACRoleNotFound, "角色不存在")
	// ErrRoleExists 角色已存在。
	ErrRoleExists = errx.NewCode(CodeRBACRoleExists, "角色已存在")
	// ErrCycle 角色继承形成环。
	ErrCycle = errx.NewCode(CodeRBACCycle, "角色继承不能形成环")
	// ErrRBACInvalid 角色名/权限参数非法。
	ErrRBACInvalid = errx.NewCode(CodeRBACInvalid, "角色或权限参数非法")
	// ErrCSRFMismatch CSRF 校验不通过。
	ErrCSRFMismatch = errx.NewCode(CodeCSRFMismatch, "CSRF 校验失败")
	// ErrSessionNotFound 会话不存在或已过期。
	ErrSessionNotFound = errx.NewCode(CodeSessionNotFound, "会话不存在或已过期")
	// ErrSessionInvalid 会话参数非法。
	ErrSessionInvalid = errx.NewCode(CodeSessionInvalid, "会话参数非法")
	// ErrSessionStoreInvalid 会话存储不可用。
	ErrSessionStoreInvalid = errx.NewCode(CodeSessionStoreInvalid, "会话存储不可用")
	// ErrMFAInvalid 多因素参数非法。
	ErrMFAInvalid = errx.NewCode(CodeMFAInvalid, "多因素参数非法")
	// ErrMFAConfigInvalid 多因素配置非法。
	ErrMFAConfigInvalid = errx.NewCode(CodeMFAConfigInvalid, "多因素配置非法")
	// ErrOAuth2Invalid OAuth2 流程失败。
	ErrOAuth2Invalid = errx.NewCode(CodeOAuth2Invalid, "OAuth2 流程失败")
	// ErrOAuth2ConfigInvalid OAuth2 配置非法。
	ErrOAuth2ConfigInvalid = errx.NewCode(CodeOAuth2ConfigInvalid, "OAuth2 配置非法")
	// ErrSecurityConfigInvalid 安全策略配置非法。
	ErrSecurityConfigInvalid = errx.NewCode(CodeSecurityConfigInvalid, "安全策略配置非法")
	// ErrStoreFull 存储容量已满。
	ErrStoreFull = errx.NewCode(CodeStoreFull, "存储容量已满")
	// ErrRBACLimit RBAC 规模超出上限。
	ErrRBACLimit = errx.NewCode(CodeRBACLimit, "RBAC 规模超出上限")
	// ErrCSRFGenerationFailed CSRF 令牌生成失败。
	ErrCSRFGenerationFailed = errx.NewCode(CodeCSRFGenerationFailed, "CSRF 令牌生成失败")
	// ErrPasswordTooWeak 明文密码不满足强度策略。
	ErrPasswordTooWeak = errx.NewCode(CodePasswordTooWeak, "密码强度不足")
	// ErrTokenMissing 请求未携带访问令牌。
	ErrTokenMissing = errx.NewCode(CodeTokenMissing, "缺少访问令牌")
	// ErrAuditQueueFull 异步审计队列已满。
	ErrAuditQueueFull = errx.NewCode(CodeAuditQueueFull, "审计队列已满")
)
