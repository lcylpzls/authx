// Package token 提供 JWT 全套算法的签发、校验、撤销与刷新令牌。
package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/errx"
)

// Claims 标准载荷 + 业务角色/权限。
type Claims struct {
	jwt.RegisteredClaims
	Roles       []string `json:"roles,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// randRead 可替换的随机源，便于测试注入失败场景。
var randRead = rand.Read

// Signer JWT 签发与校验器。
type Signer struct {
	method     jwt.SigningMethod
	signKey    any
	verifyKey  any
	issuer     string
	audience   []string
	ttl        time.Duration
	leeway     time.Duration
	kid        string
	verifyKeys map[string]any
	revoke     RevocationStore
	now        func() time.Time
}

// Option 配置 Signer 的可选参数。
type Option func(*Signer) error

// WithTTL 设置访问令牌有效期（必须为正）。
func WithTTL(ttl time.Duration) Option {
	return func(s *Signer) error {
		if ttl <= 0 {
			return errx.New(errx.KindInvalid, authx.CodeTokenConfigInvalid, "令牌有效期必须为正")
		}
		s.ttl = ttl
		return nil
	}
}

// WithIssuer 设置签发方校验（签发与校验共用）。
func WithIssuer(issuer string) Option {
	return func(s *Signer) error {
		if issuer == "" {
			return errx.New(errx.KindInvalid, authx.CodeTokenConfigInvalid, "签发方不能为空")
		}
		s.issuer = issuer
		return nil
	}
}

// WithAudience 设置受众校验（签发与校验共用）。
func WithAudience(audience ...string) Option {
	return func(s *Signer) error {
		if len(audience) == 0 {
			return errx.New(errx.KindInvalid, authx.CodeTokenConfigInvalid, "受众不能为空")
		}
		s.audience = append([]string(nil), audience...)
		return nil
	}
}

// WithRevocationStore 接入撤销列表（校验时检查 jti）。
func WithRevocationStore(store RevocationStore) Option {
	return func(s *Signer) error {
		if store == nil {
			return errx.New(errx.KindInvalid, authx.CodeTokenConfigInvalid, "撤销列表不能为空")
		}
		s.revoke = store
		return nil
	}
}

// WithClock 注入时间源（测试用）。
func WithClock(now func() time.Time) Option {
	return func(s *Signer) error {
		if now == nil {
			return errx.New(errx.KindInvalid, authx.CodeTokenConfigInvalid, "时间源不能为空")
		}
		s.now = now
		return nil
	}
}

// WithLeeway 设置签发/校验的时间容差（允许客户端时钟偏移，必须非负）。
func WithLeeway(d time.Duration) Option {
	return func(s *Signer) error {
		if d < 0 {
			return errx.New(errx.KindInvalid, authx.CodeTokenConfigInvalid, "时间容差不能为负")
		}
		s.leeway = d
		return nil
	}
}

// WithKID 设置签发密钥标识（写入 JWT 头 kid），配合多密钥轮换使用。
func WithKID(kid string) Option {
	return func(s *Signer) error {
		if kid == "" {
			return errx.New(errx.KindInvalid, authx.CodeTokenConfigInvalid, "密钥标识不能为空")
		}
		s.kid = kid
		return nil
	}
}

// WithVerificationKeys 设置多密钥验证表（kid → 验证密钥）。
// 启用后 Parse 按令牌头 kid 选择密钥，用于密钥轮换期间同时验证新旧密钥。
func WithVerificationKeys(keys map[string]any) Option {
	return func(s *Signer) error {
		if len(keys) == 0 {
			return errx.New(errx.KindInvalid, authx.CodeTokenConfigInvalid, "验证密钥表不能为空")
		}
		s.verifyKeys = make(map[string]any, len(keys))
		for k, v := range keys {
			s.verifyKeys[k] = v
		}
		return nil
	}
}

// New 使用任意签名方法与密钥构造签发器。
func New(method jwt.SigningMethod, key any, opts ...Option) (*Signer, error) {
	if method == nil || key == nil {
		return nil, errx.New(errx.KindInvalid, authx.CodeTokenConfigInvalid, "签名方法与密钥不能为空")
	}
	s := &Signer{
		method:    method,
		signKey:   key,
		verifyKey: key,
		ttl:       15 * time.Minute,
		now:       time.Now,
	}
	// 私钥签发时自动派生公钥用于验证（RSA/ECDSA/Ed25519）。
	switch k := key.(type) {
	case *rsa.PrivateKey:
		s.verifyKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		s.verifyKey = &k.PublicKey
	case ed25519.PrivateKey:
		s.verifyKey = k.Public()
	default:
		s.verifyKey = key
	}
	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// NewHS256 使用 HMAC-SHA256 构造签发器（secret 至少 32 字节）。
func NewHS256(secret []byte, opts ...Option) (*Signer, error) {
	if len(secret) < 32 {
		return nil, errx.New(errx.KindInvalid, authx.CodeTokenConfigInvalid, "HMAC 密钥至少 32 字节")
	}
	return New(jwt.SigningMethodHS256, secret, opts...)
}

// NewRS256 使用 RSA-PKCS1v15-SHA256 构造签发器。
func NewRS256(private *rsa.PrivateKey, opts ...Option) (*Signer, error) {
	if private == nil {
		return nil, errx.New(errx.KindInvalid, authx.CodeTokenConfigInvalid, "RSA 私钥不能为空")
	}
	return New(jwt.SigningMethodRS256, private, opts...)
}

// NewES256 使用 ECDSA-P256-SHA256 构造签发器。
func NewES256(private *ecdsa.PrivateKey, opts ...Option) (*Signer, error) {
	if private == nil {
		return nil, errx.New(errx.KindInvalid, authx.CodeTokenConfigInvalid, "ECDSA 私钥不能为空")
	}
	return New(jwt.SigningMethodES256, private, opts...)
}

// NewEdDSA 使用 Ed25519 构造签发器。
func NewEdDSA(private ed25519.PrivateKey, opts ...Option) (*Signer, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, errx.New(errx.KindInvalid, authx.CodeTokenConfigInvalid, "Ed25519 私钥长度非法")
	}
	return New(jwt.SigningMethodEdDSA, private, opts...)
}

// ClaimOption 配置单次签发的载荷。
type ClaimOption func(*Claims)

// WithRoles 注入角色列表。
func WithRoles(roles ...string) ClaimOption {
	return func(c *Claims) { c.Roles = append([]string(nil), roles...) }
}

// WithPermissions 注入权限列表。
func WithPermissions(permissions ...string) ClaimOption {
	return func(c *Claims) { c.Permissions = append([]string(nil), permissions...) }
}

// WithTokenTTL 覆盖默认有效期（必须为正）。
func WithTokenTTL(ttl time.Duration) ClaimOption {
	return func(c *Claims) {
		if ttl > 0 {
			c.ExpiresAt = jwt.NewNumericDate(c.IssuedAt.Time.Add(ttl))
		}
	}
}

// Sign 签发访问令牌，自动生成 jti。
func (s *Signer) Sign(subject string, opts ...ClaimOption) (string, error) {
	if subject == "" {
		return "", errx.New(errx.KindInvalid, authx.CodeTokenInvalid, "令牌主体不能为空")
	}
	now := s.now()
	jti, err := newJTI()
	if err != nil {
		return "", errx.Wrap(err, errx.KindUnavailable, authx.CodeTokenInvalid, "令牌标识生成失败")
	}
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.ttl)),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    s.issuer,
		},
	}
	if len(s.audience) > 0 {
		claims.Audience = jwt.ClaimStrings(s.audience)
	}
	for _, opt := range opts {
		opt(&claims)
	}
	tk := jwt.NewWithClaims(s.method, claims)
	if s.kid != "" {
		tk.Header["kid"] = s.kid
	}
	raw, err := tk.SignedString(s.signKey)
	if err != nil {
		return "", errx.Wrap(err, errx.KindUnavailable, authx.CodeTokenInvalid, "令牌签发失败")
	}
	return raw, nil
}

// Parse 校验签名、有效期、签发方、受众与撤销状态，返回载荷。
func (s *Signer) Parse(raw string) (Claims, error) {
	var claims Claims
	opts := []jwt.ParserOption{jwt.WithTimeFunc(s.now)}
	if s.leeway > 0 {
		opts = append(opts, jwt.WithLeeway(s.leeway))
	}
	if s.issuer != "" {
		opts = append(opts, jwt.WithIssuer(s.issuer))
	}
	for _, aud := range s.audience {
		opts = append(opts, jwt.WithAudience(aud))
	}
	// golang-jwt 契约：ParseWithClaims 返回 nil 错误时令牌必然有效，
	// 失败路径统一由 classifyParseError 映射为 authx 语义。
	if _, err := jwt.ParseWithClaims(raw, &claims, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != s.method.Alg() {
			return nil, errx.New(errx.KindUnauthorized, authx.CodeTokenSignature, "签名算法不匹配")
		}
		if s.verifyKeys != nil {
			kid, _ := t.Header["kid"].(string)
			key, ok := s.verifyKeys[kid]
			if !ok {
				return nil, errx.New(errx.KindUnauthorized, authx.CodeTokenSignature, "密钥标识不存在")
			}
			return key, nil
		}
		if kid, _ := t.Header["kid"].(string); kid != "" && s.kid != "" && kid != s.kid {
			return nil, errx.New(errx.KindUnauthorized, authx.CodeTokenSignature, "密钥标识不匹配")
		}
		return s.verifyKey, nil
	}, opts...); err != nil {
		return Claims{}, classifyParseError(err)
	}
	if s.revoke != nil && claims.ID != "" {
		revoked, rerr := s.revoke.IsRevoked(context.Background(), claims.ID)
		if rerr != nil {
			return Claims{}, errx.Wrap(rerr, errx.KindUnavailable, authx.CodeStoreInvalid, "撤销状态查询失败")
		}
		if revoked {
			return Claims{}, authx.ErrTokenRevoked
		}
	}
	return claims, nil
}

// classifyParseError 将 golang-jwt 错误映射为统一语义。
func classifyParseError(err error) error {
	if errx.Is(err, authx.CodeTokenSignature) {
		return authx.ErrTokenSignature
	}
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return authx.ErrTokenExpired
	case errors.Is(err, jwt.ErrTokenSignatureInvalid), errors.Is(err, jwt.ErrTokenMalformed):
		return authx.ErrTokenSignature
	default:
		return errx.Wrap(err, errx.KindUnauthorized, authx.CodeTokenInvalid, "令牌校验失败")
	}
}

// newJTI 生成 16 字节随机十六进制 jti；随机源失败返回错误，不回退弱标识。
func newJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := randRead(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
