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

质量基线：核心包 100% 语句覆盖、六目标 fuzz（password/token/rbac/mfa/session/security）、
race 检测、三平台 CI + govulncheck 依赖漏洞扫描、全套基准测试。

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

## 内存存储周期清理

所有内存存储（会话、刷新令牌、撤销列表、恢复码、登录守卫）均提供
`StartCleanup`，可自动回收过期条目：

```go
// 刷新令牌存储每 10 分钟清理一次过期哈希。
refreshStore := token.NewMemoryRefreshStore(nil)
cleanup := refreshStore.StartCleanup(10 * time.Minute)
defer cleanup.Stop()

// 会话存储同理。
sessStore := session.NewMemoryStore(nil)
sessCleanup := sessStore.StartCleanup(10 * time.Minute)
defer sessCleanup.Stop()
```

存储默认容量上限 10 万条，满时新增条目返回 `ErrStoreFull`；
可通过 `NewXxxWithLimit` 或 `WithMaxEntries` 调整。

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
| v0.10.0 | 令牌生命周期：kid 多密钥轮换、刷新令牌轮换助手、存储文档与清理示例（已发布） |
| v0.11.0 | OAuth2 与审计加固：客户端刷新助手、响应上限、Basic Auth、审计限长与钩子隔离（已发布） |
| v0.12.0 | 质量收口：六目标 fuzz、govulncheck、基准测试、SECURITY、终审加固（已发布，版本线完成） |
| v0.13.0 | 中间件错误响应工业化：统一 errx 结构化 JSON、可注入错误处理器（已发布） |
| v0.14.0 | 审计异步化：AsyncAuditor 批量落库、丢弃/阻塞策略、优雅关闭（已发布） |
| v0.15.0 | OAuth2 服务端可插拔存储：WithClientStore/WithTokenStore 多实例就绪（已发布） |

## 规范

- 所有日志、打印、注释与文档使用简体中文；
- 错误统一走 errx 语义（401/403 与业务错误码对齐）；
- 核心包每版本 100% 语句覆盖、race、fuzz、三平台 CI + Release；
- examples 为可执行演示（`go test ./examples/full` 验证）。
