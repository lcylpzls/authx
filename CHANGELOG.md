# Changelog

本项目遵循语义化版本（SemVer）。v1.0.0 之前允许破坏性变更。

## [v0.11.0] - 2026-08-09

### 新增

- OAuth2 客户端：
  - `RefreshToken`：使用刷新令牌自动换取新令牌；
  - 用户信息响应体上限（1 MiB）与读取失败防护，杜绝恶意大响应；
- OAuth2 服务端：
  - `WithClientBasicAuth`：token 端点启用 RFC 6749 推荐的
    客户端 Basic 认证（默认仍为表单认证）；
- 审计加固：
  - 字段长度上限（4096，防日志炸弹）；
  - 非法结果值归一为 success，防止注入任意值；
  - 钩子 panic 自动恢复并记录告警，单钩子故障不拖垮业务链路。

## [v0.10.0] - 2026-08-09

### 新增

- 多密钥轮换：
  - `WithKID`：签发密钥标识（写入 JWT 头 kid）；
  - `WithVerificationKeys`：多密钥验证表（kid → 密钥），
    轮换期内新旧密钥可同时验证；未登记 kid 或 kid 不匹配一律拒绝；
- 刷新令牌轮换：
  - `RotateRefreshToken`：校验旧令牌 → 删除旧哈希 → 签发新令牌，
    保证单次使用（旧令牌立即失效）；
- 文档：README 增加内存存储周期清理示例。

## [v0.9.0] - 2026-08-09

### 新增

- TOTP 完整化（RFC 6238 全规范）：
  - `TOTPConfig`：算法（SHA1/SHA256/SHA512）、位数（6/8）、
    时间步长可配置，`DefaultTOTPConfig` 保持 SHA1/6 位/30 秒兼容；
  - `GenerateCodeWithConfig`/`ValidateCodeWithConfig` 配置化入口，
    旧 API 行为不变；SHA-256/512 按 RFC 6238 附录 B 官方向量验证；
- 恢复码存储：
  - `RecoveryCodeStore` 接口（哈希落库、消费状态、TTL），
    `MemoryRecoveryCodeStore` 内存实现（容量上限 + 周期清理）；
  - `IssueRecoveryCodes`：生成并落库；`VerifyRecoveryCodeWithStore`：
    校验并可一次性消费；
- 密码强度策略：
  - `StrengthConfig`（长度上下限、大小写/数字/符号要求）与
    `Check`；`HashWithStrength` 在哈希前执行策略校验；
  - 默认 `Hash` 行为不变（零值策略仅长度规则）；
- JWT 时间容差：`WithLeeway` 允许签发/校验时钟偏移；

### 变更

- 新增错误码：`authx_password_too_weak`。

## [v0.8.0] - 2026-08-09

### 新增

- 会话轮换（防会话固定攻击）：
  - `session.Store` 新增 `Rotate` 方法，`MemoryStore` 实现
    （换新随机 ID、保留全部值、删除旧条目）；
  - `middleware.RotateSession`：登录后一键轮换当前会话并同步更新
    Cookie 与请求上下文；
- 会话中间件加固：
  - `WithSessionLogger`：保存失败时记录结构化告警（不再静默吞错）；
  - `WithSessionClock`：Cookie 过期时间统一使用注入时钟；
  - 请求结束后保存前重新读取上下文会话，保证轮换结果正确落库；
- CSRF 加固：
  - `CSRFProtect`：双提交 Cookie 中间件（自动签发 32 字节随机令牌、
    安全方法放行、非安全方法常量时间校验、Cookie 属性可配置）；
  - `GenerateCSRFToken`/`ValidateCSRFToken`：令牌生成与常量时间比较
    （含长度上限防御）；
  - 旧 `CSRF` 中间件同步改为常量时间比较；
- 认证中间件加固：
  - Bearer 令牌长度上限（4096），拒绝超长头；
  - `WWW-Authenticate` realm 按 RFC 7235 转义引号与反斜杠；

### 变更

- `session.Store` 接口新增 `Rotate` 方法（破坏性变更，v1 前允许）；
- 新增错误码：`authx_csrf_generation_failed`。

## [v0.7.0] - 2026-08-09

### 新增

- 统一周期清理调度（`authx.StartCleanup`/`CleanupHandle`）：
  - 会话存储、刷新令牌存储、撤销列表、登录守卫均提供
    `StartCleanup(interval)`，可自动回收过期条目；
- 内存存储容量上限（防内存无限增长）：
  - `session.MemoryStore`、`token.MemoryRefreshStore`、
    `token.MemoryRevocationStore` 默认上限 10 万条，
    满时新增条目返回 `ErrStoreFull`，更新已有条目不受影响；
  - 登录守卫 `WithMaxEntries` 配置条目上限，满时拒绝记录新主体；
  - RBAC `NewWithLimits(maxRoles, maxDepth)`：角色数量上限与
    继承深度上限（默认 1 万角色 / 32 层），超限返回 `ErrRBACLimit`；
- 防御性输入上限：
  - 恢复码单次生成数量上限（1000）；
  - TOTP 校验 skew 偏移上限（10 个窗口）；
- 随机源故障不再回退弱标识：jti 与会话 ID 生成失败时
  签发/创建明确返回错误，杜绝唯一性降级；

### 变更

- `newJTI`/`newSessionID` 由“失败回退时间戳”改为“失败返回错误”；
- 新增错误码：`authx_store_full`、`authx_rbac_limit`。

## [v0.6.0] - 2026-08-09

### 新增

- audit 包：结构化审计日志：
  - `Event`（动作/主体/对象/结果/详情/IP/时间）与 `Auditor`；
  - logx 结构化输出 + `AddHook` 持久化钩子（落库/告警）；
- security 包：登录防爆破守卫：
  - `LoginGuard`：滑动窗口失败计数、达到阈值自动锁定、
    `IsLocked`/`Reset`/`Cleanup`，时间源可注入；
- examples/full：全套组件组合示例（密码 → 令牌 → RBAC → 会话 →
  TOTP → 防爆破 → OAuth2 → webx 装配），`run()` 可测试执行；

## [v0.5.0] - 2026-08-09

### 新增

- oauth2 包：客户端与服务端：
  - 客户端：授权码 + PKCE（S256）、令牌交换、用户信息拉取、
    携带令牌的标准库 HTTP 客户端；
  - 服务端：授权码 + PKCE + 刷新令牌，内存客户端/令牌存储，
    未登录 401 或按 OAuth2 规范重定向错误；
  - webx 适配：`AuthorizeWebxHandler`/`TokenWebxHandler`，
    登录态经 `WithUserID` 写入请求上下文；

### 安全修复

- password 包：解析哈希时增加参数上限（内存 ≤256MiB、迭代 ≤1000、
  盐 ≤1024 字节、密钥 ≤4096 字节），修复 fuzz 发现的恶意哈希
  超大内存/CPU 参数可导致进程崩溃的问题（v0.4.0 CI fuzz 失败根因）；
- 保留 fuzz 崩溃输入作为回归用例（`testdata/fuzz/FuzzVerify/...`）。

## [v0.4.0] - 2026-08-09

### 新增

- session 包：会话模型与存储：
  - `Session`（ID + 键值对）、`Store` 接口（Create/Get/Save/Delete）；
  - `MemoryStore` 内存实现（TTL 过期清理、ID 冲突重试、深拷贝隔离）；
- middleware 会话中间件：
  - `Session`：读取/创建会话、种 Cookie（Secure/HttpOnly/SameSite 可配）、
    请求结束自动保存，处理器内 `SessionFrom` 读取；
- mfa 包：多因素认证：
  - TOTP（RFC 6238，HMAC-SHA1、6 位、30s 周期、skew 窗口）；
  - `GenerateSecret`/`GenerateCode`/`ValidateCode`/`ProvisioningURI`；
  - 恢复码：生成（16 字节 base32 分组）、SHA-256 哈希存储、常量时间校验；
- 新增错误码：会话（不存在/非法/存储不可用）、MFA（非法/配置非法）。

## [v0.3.0] - 2026-08-09

### 新增

- rbac 包：角色-权限模型：
  - `AddRole`/`AddPermission`/`Inherit`（角色继承，自引用与环检测）；
  - `HasPermission`/`HasAnyPermission`/`HasAllPermissions`/`PermissionsOf`；
  - 读写并发安全，适合启动期加载 + 请求期只读；
- middleware 包：webx 认证授权中间件：
  - `Auth`：Bearer Token 解析、令牌校验、身份注入，401 标准响应；
  - `RequirePermission`/`RequireRole`：RBAC 鉴权，403 标准响应；
  - `CSRF`：双提交 Cookie 校验，安全方法自动放行；
  - `ClaimsFrom`/`UserID`：处理器内读取用户身份；
- 新增错误码：RBAC 角色/环/权限、Forbidden、CSRF。

## [v0.2.0] - 2026-08-09

### 新增

- token 包：JWT 全套算法签发与校验：
  - `Signer`：HS256/RS256/ES256/EdDSA 构造器，私钥自动派生公钥验证；
  - `Claims`：标准载荷 + 角色/权限，`Sign`/`Parse` 支持签发方、受众、
    有效期、撤销校验；
  - `WithTTL`/`WithIssuer`/`WithAudience`/`WithRevocationStore`/`WithClock`；
- token 刷新令牌：
  - `IssueRefreshToken`/`ValidateRefreshToken`/`ConsumeRefreshToken`，
    明文不落库（SHA-256 哈希存储）；
  - `RefreshStore` 接口 + 内存实现（可接 Redis 等外部实现）；
- token 撤销列表：`RevocationStore` 接口 + 内存实现（按 jti，TTL 清理）；
- fuzz：`FuzzParse`（任意输入解析不 panic）。

## [v0.1.0] - 2026-08-09

### 新增

- password 包：Argon2id 密码哈希（RFC 9106）：
  - `Hash`：生成 `$argon2id$v=19$m=...,t=...,p=...$盐$密钥` 标准编码；
  - `Verify`：解析并校验，常量时间比较，格式错误返回 errx 错误；
  - `NeedsRehash`：参数迁移检测（登录时惰性升级）；
  - 默认参数按 OWASP 推荐（m=19MiB、t=2、p=1），可配置并校验；
- 根包错误码与预定义错误（errx 集成，401/400 语义对齐）；
- CI：三平台 test + race + coverage + fuzz；Release：tag 自动发布。
