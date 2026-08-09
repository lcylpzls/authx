# Changelog

本项目遵循语义化版本（SemVer）。v1.0.0 之前允许破坏性变更。

## [v0.1.0] - 2026-08-09

### 新增

- password 包：Argon2id 密码哈希（RFC 9106）：
  - `Hash`：生成 `$argon2id$v=19$m=...,t=...,p=...$盐$密钥` 标准编码；
  - `Verify`：解析并校验，常量时间比较，格式错误返回 errx 错误；
  - `NeedsRehash`：参数迁移检测（登录时惰性升级）；
  - 默认参数按 OWASP 推荐（m=19MiB、t=2、p=1），可配置并校验；
- 根包错误码与预定义错误（errx 集成，401/400 语义对齐）；
- CI：三平台 test + race + coverage + fuzz；Release：tag 自动发布。
