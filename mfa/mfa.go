// Package mfa 提供 TOTP（RFC 6238）与恢复码。
package mfa

import (
	"context"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/cryptox"
	"github.com/lcylpzls/errx"
	"github.com/lcylpzls/validx"
)

const (
	defaultPeriod     = 30 * time.Second
	secretBytes       = 20
	recoveryBytes     = 16
	recoveryPadding   = "-"
	maxRecoveryCodes  = 1000 // 单次生成恢复码数量上限（防 DoS）
	maxValidationSkew = 10   // TOTP 校验窗口偏移上限（防循环放大）
)

// randRead 可替换的随机源，便于测试注入失败场景。
var randRead = cryptox.RandomBytes

// Algorithm TOTP 使用的哈希算法。
type Algorithm uint8

// 支持的 TOTP 哈希算法。
const (
	AlgorithmSHA1 Algorithm = iota
	AlgorithmSHA256
	AlgorithmSHA512
)

// TOTPConfig TOTP 生成配置。
type TOTPConfig struct {
	// Algorithm 哈希算法（SHA1/SHA256/SHA512）。
	Algorithm Algorithm
	// Digits 验证码位数（6 或 8）。
	Digits int
	// Period 时间步长（必须为正）。
	Period time.Duration
}

// DefaultTOTPConfig 返回 RFC 6238 默认配置（SHA1、6 位、30 秒）。
func DefaultTOTPConfig() TOTPConfig {
	return TOTPConfig{Algorithm: AlgorithmSHA1, Digits: 6, Period: defaultPeriod}
}

// init 注册 TOTP 配置校验规则到 validx 全局规则表，错误码保持 authx 语义。
func init() {
	_ = validx.RegisterRule("authx_totp_config", func(value any, param, path string) error {
		// 内部调用保证 value 为 TOTPConfig。
		c := value.(TOTPConfig)
		switch c.Algorithm {
		case AlgorithmSHA1, AlgorithmSHA256, AlgorithmSHA512:
		default:
			return authx.ErrMFAConfigInvalid
		}
		if c.Digits != 6 && c.Digits != 8 {
			return authx.ErrMFAConfigInvalid
		}
		if c.Period < time.Second {
			return authx.ErrMFAConfigInvalid
		}
		return nil
	})
}

// Validate 校验 TOTP 配置（统一走 validx 规则）。
func (c TOTPConfig) Validate() error {
	return validx.ValidateField(c, "authx_totp_config")
}

// hashName 返回算法对应的 cryptox 算法名。
func (c TOTPConfig) hashName() string {
	switch c.Algorithm {
	case AlgorithmSHA256:
		return "SHA256"
	case AlgorithmSHA512:
		return "SHA512"
	default:
		return "SHA1"
	}
}

// GenerateSecret 生成 20 字节随机密钥（base32 无填充，适合录入身份验证器）。
func GenerateSecret() (string, error) {
	b, err := randRead(secretBytes)
	if err != nil {
		return "", authx.ErrMFAInvalid
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// GenerateCode 生成指定时刻的 TOTP 验证码（RFC 6238 默认配置）。
func GenerateCode(secret string, at time.Time) (string, error) {
	return GenerateCodeWithConfig(secret, at, DefaultTOTPConfig())
}

// GenerateCodeWithConfig 按配置生成指定时刻的 TOTP 验证码。
func GenerateCodeWithConfig(secret string, at time.Time, cfg TOTPConfig) (string, error) {
	if err := cfg.Validate(); err != nil {
		return "", err
	}
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	counter := uint64(at.Unix()) / uint64(cfg.Period.Seconds())
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	// 配置已校验算法，密钥非空，SignHMACWithHash 不会失败。
	sum, _ := cryptox.SignHMACWithHash(cfg.hashName(), key, buf[:])
	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < cfg.Digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", cfg.Digits, code%mod), nil
}

// ValidateCode 校验验证码，允许前后 skew 个时间窗口。
func ValidateCode(secret, code string, at time.Time, skew uint) (bool, error) {
	return ValidateCodeWithConfig(secret, code, at, skew, DefaultTOTPConfig())
}

// ValidateCodeWithConfig 按配置校验验证码，允许前后 skew 个时间窗口。
func ValidateCodeWithConfig(secret, code string, at time.Time, skew uint, cfg TOTPConfig) (bool, error) {
	if err := cfg.Validate(); err != nil {
		return false, err
	}
	if skew > maxValidationSkew {
		return false, authx.ErrMFAConfigInvalid
	}
	if len(code) != cfg.Digits {
		return false, authx.ErrMFAInvalid
	}
	for _, d := range code {
		if d < '0' || d > '9' {
			return false, authx.ErrMFAInvalid
		}
	}
	for i := -int64(skew); i <= int64(skew); i++ {
		at2 := at.Add(time.Duration(i) * cfg.Period)
		got, err := GenerateCodeWithConfig(secret, at2, cfg)
		if err != nil {
			return false, err
		}
		if cryptox.ConstantTimeEquals([]byte(got), []byte(code)) {
			return true, nil
		}
	}
	return false, nil
}

// ProvisioningURI 生成 otpauth:// 二维码内容。
func ProvisioningURI(secret, account, issuer string) string {
	label := issuer + ":" + account
	return "otpauth://totp/" + url.PathEscape(label) +
		"?secret=" + url.QueryEscape(secret) +
		"&issuer=" + url.QueryEscape(issuer) +
		"&algorithm=SHA1&digits=6&period=30"
}

// GenerateRecoveryCodes 生成 count 个恢复码（16 字节随机，base32 无填充，4 位一组）。
func GenerateRecoveryCodes(count int) ([]string, error) {
	if count <= 0 || count > maxRecoveryCodes {
		return nil, authx.ErrMFAConfigInvalid
	}
	codes := make([]string, 0, count)
	for i := 0; i < count; i++ {
		b, err := randRead(recoveryBytes)
		if err != nil {
			return nil, authx.ErrMFAInvalid
		}
		raw := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
		var parts []string
		for j := 0; j < len(raw); j += 4 {
			end := j + 4
			if end > len(raw) {
				end = len(raw)
			}
			parts = append(parts, raw[j:end])
		}
		codes = append(codes, strings.Join(parts, recoveryPadding))
	}
	return codes, nil
}

// HashRecoveryCode 计算恢复码哈希（存储用，明文不落库）。
func HashRecoveryCode(code string) string {
	return fmt.Sprintf("%x", cryptox.SHA256([]byte(code)))
}

// RecoveryCodeStore 恢复码存储接口（哈希落库、消费状态，可接 Redis 等外部实现）。
type RecoveryCodeStore interface {
	// Save 保存恢复码哈希，ttl 内有效。
	Save(ctx context.Context, hash string, ttl time.Duration) error
	// Validate 判断哈希是否存在、未消费且未过期。
	Validate(ctx context.Context, hash string) (bool, error)
	// Consume 消费恢复码（单次使用）。
	Consume(ctx context.Context, hash string) error
	// Delete 删除恢复码。
	Delete(ctx context.Context, hash string) error
}

const defaultMaxEntries = 100000 // 恢复码存储容量上限（防内存无限增长）

// recoveryItem 内存条目。
type recoveryItem struct {
	consumed bool
	expires  time.Time
}

// MemoryRecoveryCodeStore 内存恢复码存储。
type MemoryRecoveryCodeStore struct {
	mu         sync.Mutex
	items      map[string]recoveryItem
	now        func() time.Time
	maxEntries int
}

// NewMemoryRecoveryCodeStore 构造内存恢复码存储。
func NewMemoryRecoveryCodeStore(now func() time.Time) *MemoryRecoveryCodeStore {
	return NewMemoryRecoveryCodeStoreWithLimit(now, defaultMaxEntries)
}

// NewMemoryRecoveryCodeStoreWithLimit 构造带容量上限的内存恢复码存储。
func NewMemoryRecoveryCodeStoreWithLimit(now func() time.Time, maxEntries int) *MemoryRecoveryCodeStore {
	if maxEntries <= 0 {
		panic("authx: 恢复码存储容量上限必须为正")
	}
	if now == nil {
		now = time.Now
	}
	return &MemoryRecoveryCodeStore{items: make(map[string]recoveryItem), now: now, maxEntries: maxEntries}
}

// Save 保存恢复码哈希。
func (s *MemoryRecoveryCodeStore) Save(_ context.Context, hash string, ttl time.Duration) error {
	if hash == "" || ttl <= 0 {
		return authx.ErrMFAInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[hash]; !ok && len(s.items) >= s.maxEntries {
		return authx.ErrStoreFull
	}
	s.items[hash] = recoveryItem{expires: s.now().Add(ttl)}
	return nil
}

// Validate 校验哈希存在、未消费且未过期。
func (s *MemoryRecoveryCodeStore) Validate(_ context.Context, hash string) (bool, error) {
	if hash == "" {
		return false, authx.ErrMFAInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[hash]
	if !ok || item.consumed {
		return false, nil
	}
	if !s.now().Before(item.expires) {
		delete(s.items, hash)
		return false, nil
	}
	return true, nil
}

// Consume 消费恢复码（单次使用）。
func (s *MemoryRecoveryCodeStore) Consume(_ context.Context, hash string) error {
	if hash == "" {
		return authx.ErrMFAInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[hash]
	if !ok {
		return authx.ErrMFAInvalid
	}
	if !s.now().Before(item.expires) {
		delete(s.items, hash)
		return authx.ErrMFAInvalid
	}
	item.consumed = true
	s.items[hash] = item
	return nil
}

// Delete 删除恢复码。
func (s *MemoryRecoveryCodeStore) Delete(_ context.Context, hash string) error {
	if hash == "" {
		return authx.ErrMFAInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, hash)
	return nil
}

// Cleanup 清理过期条目，返回清理数量。
func (s *MemoryRecoveryCodeStore) Cleanup() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	removed := 0
	for k, item := range s.items {
		if !now.Before(item.expires) {
			delete(s.items, k)
			removed++
		}
	}
	return removed
}

// StartCleanup 启动周期性过期清理（间隔必须为正），返回句柄；Stop 停止并等待退出。
func (s *MemoryRecoveryCodeStore) StartCleanup(interval time.Duration) *authx.CleanupHandle {
	return authx.StartCleanup(interval, s.Cleanup)
}

// IssueRecoveryCodes 生成 count 个恢复码并存储其哈希，返回明文列表。
// 存储失败时返回错误；已存储的条目不会回滚（调用方可删除或重新签发）。
func IssueRecoveryCodes(ctx context.Context, store RecoveryCodeStore, count int, ttl time.Duration) ([]string, error) {
	if store == nil {
		return nil, errx.NewCode(authx.CodeMFAConfigInvalid, "恢复码存储不能为空")
	}
	codes, err := GenerateRecoveryCodes(count)
	if err != nil {
		return nil, err
	}
	for _, code := range codes {
		if err := store.Save(ctx, HashRecoveryCode(code), ttl); err != nil {
			return nil, errx.Wrap(err, errx.KindUnavailable, authx.CodeMFAInvalid, "恢复码存储失败")
		}
	}
	return codes, nil
}

// VerifyRecoveryCodeWithStore 校验恢复码；consume 为 true 时消费（单次使用）。
func VerifyRecoveryCodeWithStore(ctx context.Context, store RecoveryCodeStore, code string, consume bool) (bool, error) {
	if store == nil || code == "" {
		return false, authx.ErrMFAInvalid
	}
	hash := HashRecoveryCode(code)
	ok, err := store.Validate(ctx, hash)
	if err != nil || !ok {
		return ok, err
	}
	if consume {
		if err := store.Consume(ctx, hash); err != nil {
			return false, errx.Wrap(err, errx.KindUnavailable, authx.CodeMFAInvalid, "恢复码消费失败")
		}
	}
	return true, nil
}

// VerifyRecoveryCode 常量时间校验恢复码。
func VerifyRecoveryCode(hash, code string) bool {
	return cryptox.ConstantTimeEquals([]byte(hash), []byte(HashRecoveryCode(code)))
}

// decodeSecret 解码 base32 密钥（兼容带/不带填充）。
func decodeSecret(secret string) ([]byte, error) {
	secret = strings.TrimSpace(strings.ToUpper(secret))
	secret = strings.TrimRight(secret, "=")
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil || len(b) == 0 {
		return nil, authx.ErrMFAInvalid
	}
	return b, nil
}
