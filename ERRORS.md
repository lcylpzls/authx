# 错误码清单

所有错误统一使用 errx 语义（`errx.Is(err, Code)` 判断），
HTTP 状态码由 Kind 映射（默认中间件响应见 [middleware](README.md)）。

| 错误码 | 含义 | Kind | 建议 HTTP |
| --- | --- | --- | --- |
| `authx_password_hash_invalid` | 密码哈希格式无效或损坏 | invalid_argument | 400 |
| `authx_password_mismatch` | 明文与哈希不匹配（未认证） | unauthorized | 401 |
| `authx_password_too_long` | 明文密码超过长度上限 | invalid_argument | 400 |
| `authx_password_too_short` | 明文密码低于长度下限 | invalid_argument | 400 |
| `authx_password_too_weak` | 明文密码不满足强度策略 | invalid_argument | 400 |
| `authx_password_config_invalid` | 哈希参数非法 | invalid_argument | 400 |
| `authx_password_internal` | 哈希/校验内部失败 | unavailable | 503 |
| `authx_token_invalid` | 令牌格式或载荷非法 | unauthorized | 401 |
| `authx_token_missing` | 请求未携带访问令牌 | unauthorized | 401 |
| `authx_token_expired` | 令牌已过期 | unauthorized | 401 |
| `authx_token_signature` | 令牌签名无效或算法不匹配 | unauthorized | 401 |
| `authx_token_revoked` | 令牌已撤销 | unauthorized | 401 |
| `authx_token_config_invalid` | 令牌配置非法 | invalid_argument | 400 |
| `authx_refresh_token_invalid` | 刷新令牌无效或已使用 | unauthorized | 401 |
| `authx_store_invalid` | 存储参数非法 | invalid_argument | 400 |
| `authx_store_full` | 存储容量已满 | unavailable | 503 |
| `authx_forbidden` | 已认证但无权限 | forbidden | 403 |
| `authx_rbac_role_not_found` | 角色不存在 | invalid_argument | 400 |
| `authx_rbac_role_exists` | 角色已存在 | already_exists | 409 |
| `authx_rbac_cycle` | 角色继承形成环 | invalid_argument | 400 |
| `authx_rbac_limit` | RBAC 规模超出上限 | invalid_argument | 400 |
| `authx_rbac_invalid` | 角色/权限参数非法 | invalid_argument | 400 |
| `authx_csrf_mismatch` | CSRF 校验不通过 | forbidden | 403 |
| `authx_csrf_generation_failed` | CSRF 令牌生成失败 | unavailable | 503 |
| `authx_session_not_found` | 会话不存在或已过期 | unauthorized | 401 |
| `authx_session_invalid` | 会话参数非法 | invalid_argument | 400 |
| `authx_session_store_invalid` | 会话存储不可用 | unavailable | 503 |
| `authx_mfa_invalid` | MFA 参数非法（密钥/验证码） | invalid_argument | 400 |
| `authx_mfa_config_invalid` | MFA 配置非法 | invalid_argument | 400 |
| `authx_oauth2_invalid` | OAuth2 流程失败 | unauthorized | 401 |
| `authx_oauth2_config_invalid` | OAuth2 配置非法 | invalid_argument | 400 |
| `authx_security_config_invalid` | 安全策略配置非法 | invalid_argument | 400 |
| `authx_audit_queue_full` | 异步审计队列已满（事件丢弃） | rate_limited | 429 |

## 判断方式

```go
import "github.com/lcylpzls/errx"

if errx.Is(err, authx.CodeTokenExpired) {
    // 令牌已过期。
}
```

预定义错误值（`authx.ErrTokenExpired` 等）可用 `errors.Is` 判断。
