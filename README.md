# authx

**工业级认证与授权组件库**，与 errx / logx / webx 深度集成：

- 密码哈希：Argon2id（RFC 9106），支持参数迁移与常量时间比较；
- 令牌：JWT 全套算法（HS/RS/ES/EdDSA）、刷新令牌、撤销列表；
- 授权：RBAC 角色/权限模型（支持角色继承与环检测）；
- 集成：webx 认证/权限/CSRF 中间件（Bearer 校验、401/403 标准响应）；
- 会话：Session 存储接口 + 内存实现 + webx 会话中间件（自动落库）；
- 多因素：TOTP（RFC 6238）与恢复码；
- OAuth2：客户端（授权码 + PKCE）与服务端（授权码 + PKCE + 刷新令牌）；
- 审计：结构化审计日志（logx 集成）+ 持久化钩子；
- 安全：登录失败计数、账号锁定、滑动窗口清理。

## 目录

```
authx/
├── errors.go / config.go     # errx 错误码与全局配置
├── password/                 # Argon2id 哈希、校验、参数迁移
├── token/                    # JWT 全套算法、刷新令牌、撤销列表
├── rbac/                     # 角色/权限模型、角色继承
├── middleware/               # webx 认证/权限/CSRF/会话中间件
├── session/                  # 会话模型与存储接口
├── mfa/                      # TOTP 与恢复码
├── oauth2/                   # OAuth2 客户端与授权服务端
├── audit/                    # 结构化审计日志
├── security/                 # 登录防爆破守卫
└── examples/full/            # 全套组合示例
```

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
| v0.4.0 | session + mfa：会话与 TOTP（已发布） |
| v0.5.0 | oauth2：客户端与授权码/PKCE 服务端（已发布） |
| v0.6.0 | audit + security：审计、锁定、频控与 full 示例（已发布，版本线完成） |
| v0.7.0 | 防 DoS 与资源上限：容量上限、周期清理、输入上限、随机源失败报错（已发布） |
| v0.8.0 | 会话与 CSRF 加固：会话轮换、保存失败日志、CSRF 令牌、Auth 上限与转义（已发布） |
| v0.9.0 | 密码学完整化：TOTP 算法/位数/周期、恢复码存储、密码强度、JWT leeway（已发布） |

## 规范

- 所有日志、打印、注释与文档使用简体中文；
- 错误统一走 errx 语义（401/403 与业务错误码对齐）；
- 核心包每版本 100% 语句覆盖、race、fuzz、三平台 CI + Release；
- examples 为可执行演示（`go test ./examples/full` 验证）。
