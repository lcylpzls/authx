# Changelog

本项目遵循语义化版本（SemVer）。v1.0.0 之前允许破坏性变更。

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
