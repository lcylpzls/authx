// Package security 提供登录防护：失败计数、账号锁定与窗口清理。
package security

import (
	"sync"
	"time"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/errx"
)

// LoginGuard 登录防爆破守卫（按主体 key 计数与锁定）。
type LoginGuard struct {
	maxFailures  int
	lockDuration time.Duration
	window       time.Duration
	mu           sync.Mutex
	failures     map[string][]time.Time
	locked       map[string]time.Time
	now          func() time.Time
}

// Option LoginGuard 配置项。
type Option func(*LoginGuard) error

// WithFailureWindow 设置失败计数窗口（滑动窗口内计数有效）。
func WithFailureWindow(d time.Duration) Option {
	return func(g *LoginGuard) error {
		if d <= 0 {
			return errx.New(errx.KindInvalid, authx.CodeSecurityConfigInvalid, "失败窗口必须为正")
		}
		g.window = d
		return nil
	}
}

// WithClock 注入时间源（测试用）。
func WithClock(now func() time.Time) Option {
	return func(g *LoginGuard) error {
		if now == nil {
			return errx.New(errx.KindInvalid, authx.CodeSecurityConfigInvalid, "时间源不能为空")
		}
		g.now = now
		return nil
	}
}

// NewLoginGuard 构造登录守卫。
func NewLoginGuard(maxFailures int, lockDuration time.Duration, opts ...Option) (*LoginGuard, error) {
	if maxFailures <= 0 || lockDuration <= 0 {
		return nil, errx.New(errx.KindInvalid, authx.CodeSecurityConfigInvalid, "最大失败次数与锁定时长必须为正")
	}
	g := &LoginGuard{
		maxFailures:  maxFailures,
		lockDuration: lockDuration,
		window:       10 * time.Minute,
		failures:     make(map[string][]time.Time),
		locked:       make(map[string]time.Time),
		now:          time.Now,
	}
	for _, opt := range opts {
		if err := opt(g); err != nil {
			return nil, err
		}
	}
	return g, nil
}

// RecordFailure 记录一次失败；返回 true 表示已达到锁定阈值或已处于锁定。
func (g *LoginGuard) RecordFailure(key string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	if until, ok := g.locked[key]; ok && now.Before(until) {
		return true
	}
	cutoff := now.Add(-g.window)
	kept := g.failures[key][:0]
	for _, t := range g.failures[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	g.failures[key] = kept
	if len(kept) >= g.maxFailures {
		g.locked[key] = now.Add(g.lockDuration)
		delete(g.failures, key)
		return true
	}
	return false
}

// IsLocked 判断主体当前是否被锁定（过期自动解锁）。
func (g *LoginGuard) IsLocked(key string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	until, ok := g.locked[key]
	if !ok {
		return false
	}
	if !g.now().Before(until) {
		delete(g.locked, key)
		return false
	}
	return true
}

// Reset 清除主体的锁定与失败计数（登录成功后调用）。
func (g *LoginGuard) Reset(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.locked, key)
	delete(g.failures, key)
}

// Cleanup 清理过期锁定与窗口外失败记录，返回清理项数。
func (g *LoginGuard) Cleanup() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	removed := 0
	for key, until := range g.locked {
		if !now.Before(until) {
			delete(g.locked, key)
			removed++
		}
	}
	cutoff := now.Add(-g.window)
	for key, list := range g.failures {
		kept := list[:0]
		for _, t := range list {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(g.failures, key)
			removed++
		} else {
			g.failures[key] = kept
		}
	}
	return removed
}
