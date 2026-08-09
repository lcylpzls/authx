// Package mfa 提供 TOTP（RFC 6238）与恢复码。
package mfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/lcylpzls/authx"
)

const (
	defaultPeriod   = 30 * time.Second
	secretBytes     = 20
	recoveryBytes   = 16
	recoveryPadding = "-"
)

// randRead 可替换的随机源，便于测试注入失败场景。
var randRead = rand.Read

// GenerateSecret 生成 20 字节随机密钥（base32 无填充，适合录入身份验证器）。
func GenerateSecret() (string, error) {
	b := make([]byte, secretBytes)
	if _, err := randRead(b); err != nil {
		return "", authx.ErrMFAInvalid
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// GenerateCode 生成指定时刻的 TOTP 验证码（HMAC-SHA1，6 位）。
func GenerateCode(secret string, at time.Time) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	counter := uint64(at.Unix()) / uint64(defaultPeriod.Seconds())
	mac := hmac.New(sha1.New, key)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	_, _ = mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := (binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", code), nil
}

// ValidateCode 校验验证码，允许前后 skew 个时间窗口。
func ValidateCode(secret, code string, at time.Time, skew uint) (bool, error) {
	if len(code) != 6 {
		return false, authx.ErrMFAInvalid
	}
	for _, d := range code {
		if d < '0' || d > '9' {
			return false, authx.ErrMFAInvalid
		}
	}
	for i := -int64(skew); i <= int64(skew); i++ {
		at2 := at.Add(time.Duration(i) * defaultPeriod)
		got, err := GenerateCode(secret, at2)
		if err != nil {
			return false, err
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(code)) == 1 {
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
	if count <= 0 {
		return nil, authx.ErrMFAConfigInvalid
	}
	codes := make([]string, 0, count)
	for i := 0; i < count; i++ {
		b := make([]byte, recoveryBytes)
		if _, err := randRead(b); err != nil {
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
	sum := sha256.Sum256([]byte(code))
	return fmt.Sprintf("%x", sum)
}

// VerifyRecoveryCode 常量时间校验恢复码。
func VerifyRecoveryCode(hash, code string) bool {
	return subtle.ConstantTimeCompare([]byte(hash), []byte(HashRecoveryCode(code))) == 1
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
