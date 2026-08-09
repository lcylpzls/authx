# authx

**工业级认证与授权组件库**，与 errx / logx / webx 深度集成：

- 密码哈希：Argon2id（RFC 9106），支持参数迁移与常量时间比较；
- 令牌：JWT 全套算法（HS/RS/ES/EdDSA）、刷新令牌、撤销列表；
- 授权：RBAC 角色/权限模型（支持角色继承与环检测）；
- 集成：webx 认证/权限/CSRF 中间件（Bearer 校验、401/403 标准响应）；
- 增强：Session、TOTP 多因素、OAuth2/OIDC、审计与安全策略（规划中）。

## 安装

```powershell
go get github.com/lcylpzls/authx
```

## 快速开始（v0.1.0：密码哈希）

```go
import (
	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/authx/password"
)

// 注册：哈希明文并存储
hash, err := password.Hash("password123", authx.DefaultPasswordConfig())

// 登录：校验明文
ok, err := password.Verify(hash, "password123")

// 惰性迁移：参数升级时重新哈希
need, err := password.NeedsRehash(hash, authx.DefaultPasswordConfig())
```

## 版本路线

| 版本 | 内容 |
| --- | --- |
| v0.1.0 | password：Argon2id 哈希、校验、参数迁移（已发布） |
| v0.2.0 | token：JWT 全套、刷新令牌、撤销（已发布） |
| v0.3.0 | rbac + middleware：webx 认证/权限/CSRF（已发布） |
| v0.4.0 | session + mfa：会话与 TOTP |
| v0.5.0 | oauth2：客户端与授权码/PKCE 服务端 |
| v0.6.0 | audit + security：审计、锁定、频控与 full 示例 |

## 规范

- 所有日志、打印、注释与文档使用简体中文；
- 错误统一走 errx 语义（401/403 与业务错误码对齐）；
- 每版本 100% 语句覆盖、race、fuzz、三平台 CI + Release。
