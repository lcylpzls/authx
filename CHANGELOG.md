# Changelog

本项目遵循语义化版本（SemVer）。v1.0.0 之前允许破坏性变更。

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
