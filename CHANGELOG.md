# Changelog

本项目遵循语义化版本（SemVer）。v1.0.0 之前允许破坏性变更。

## [v0.18.0] - 2026-08-09

### 新增

- TTL/过期边界测试矩阵：访问令牌、撤销列表、刷新令牌、会话
  （读取与轮换）、恢复码（校验与消费）、账号锁定——
  全部覆盖“到期前 1ns 有效 / 到期瞬间失效”的精确边界；
- 高并发基准：会话存储、刷新令牌存储、登录守卫的
  `RunParallel` 压测 benchmark；
- fuzz 扩展到 9 个目标：新增 audit（审计事件）、middleware
  （CSRF/Bearer）、oauth2（配置校验），CI 每目标 10 秒。

## [v0.17.0] - 2026-08-09

### 新增

- examples/login-demo 全链路演示：
  - 注册（密码强度 + Argon2id）→ 登录（防爆破 + 会话轮换 + JWT）→
    会话（HMAC 签名 Cookie）→ CSRF（双提交 + Origin 校验）→
    RBAC 权限 → 审计（异步）→ MFA（TOTP）→ OAuth2 端点；
  - `TestAppFlow` 覆盖注册/重复注册/弱密码/登录/鉴权/管理员/MFA 全流程；
- ERRORS.md：全部错误码、Kind、建议 HTTP 状态与判断方式清单。

## [v0.16.0] - 2026-08-09

### 新增

- 会话 Cookie 纵深防御：
  - `WithSessionSigningKey`：会话 Cookie 值 HMAC-SHA256 签名，
    篡改或伪造的会话 ID 一律视为无会话并重建；
  - 轮换会话后签名同步更新；Cookie 值长度上限 512；
- CSRF 来源校验：
  - `WithCSRFAllowedOrigins`：非安全方法校验 Origin 精确匹配，
    无 Origin 时回退校验 Referer 的 scheme://host；
  - Origin/Referer 长度上限 2048，未配置时保持跳过校验的旧行为。

## [v0.15.0] - 2026-08-09

### 新增

- OAuth2 服务端可插拔存储：
  - `WithClientStore`：注入自定义客户端存储（替代内置内存客户端表）；
  - `WithTokenStore`：注入自定义令牌存储（替代内置内存令牌存储）；
  - 多实例共享部署不再受单机内存限制，可接入 Redis 等外部实现；
  - 空存储返回配置错误，杜绝静默回退。

## [v0.14.0] - 2026-08-09

### 新增

- 审计异步化：
  - `AsyncAuditor`：事件入队后立即返回，后台批量输出与落库，
    业务请求不被审计阻塞；
  - 配置项：`WithBatchSize`（批量阈值）、`WithFlushInterval`（定时冲刷）、
    `WithDropPolicy`（队列满时丢弃新事件或阻塞）；
  - `Dropped()` 丢弃计数、`Stop()` 优雅关闭（排空队列后退出，幂等）；
  - 停止后拒绝新事件，杜绝残留；
- 新增错误码：`authx_audit_queue_full`。

## [v0.13.0] - 2026-08-09

### 新增

- 中间件错误响应工业化：
  - `ErrorResponse` 统一 JSON 错误体（code/kind/message，errx 语义）；
  - `DefaultErrorHandler` 默认结构化输出，挂载于 webx 标准化响应的 data；
  - `WithAuthErrorHandler`/`WithCSRFErrorHandler`/`WithSessionErrorHandler`
    可注入自定义错误处理器（状态码与响应体完全可控）；
  - Auth/权限/CSRF/会话全部错误路径统一走结构化响应；
- 新增错误码：`authx_token_missing`（未携带访问令牌）。

## [v0.12.0] - 2026-08-09

### 新增

- fuzz 扩展到 6 个目标：password、token、rbac、mfa、session、security，
  CI 每目标 10 秒短程（FuzzRBAC/FuzzTOTP/FuzzSessionStore/FuzzLoginGuard）；
- CI 新增 govulncheck 依赖漏洞扫描 job；
- 基准测试：password（哈希/校验）、token（签发/校验）、TOTP（生成/校验）、
  RBAC（权限判断）、会话（保存/读取）、登录守卫（失败记录）、CSRF（令牌比较）；
- SECURITY.md：漏洞报告流程、支持范围、安全基线与实践建议；
- godoc 示例：password/token/mfa/session 各包 Example 演示。

### 安全修复（终审）

- TOTP `Period` 下限调整为 1 秒：fuzz 发现亚秒周期会导致
  `Seconds()` 为 0 触发除零 panic（恶意配置可拒绝服务）；
- 密码哈希解析：base64 解码前按编码长度预检，避免超长输入
  触发大内存分配；
- JWT 校验：原始令牌长度上限 64 KiB，拒绝超长输入。

### 版本线

- v0.1.0 - v0.12.0 全部完成并发布，按计划**停止于 v0.12.0**，不发布 v1.0.0；
- 核心包语句覆盖率 100%，六目标 fuzz、race、三平台 CI、
  govulncheck 全绿。

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
