// Package security 提供登录防护：失败计数、账号锁定与窗口清理。
package security

import (
	"context"
	"sync"
	"time"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/errx"
)

const defaultMaxEntries = 100000 // 守卫条目数量上限（防内存无限增长）

// GuardPolicy 描述登录防爆破策略，供可插拔存储原子执行。
type GuardPolicy struct {
	// MaxFailures 是窗口内允许的最大失败次数。
	MaxFailures int
	// FailureWindow 是失败计数滑动窗口。
	FailureWindow time.Duration
	// LockDuration 是达到阈值后的锁定时长。
	LockDuration time.Duration
}

// GuardStore 是登录守卫存储契约；实现必须保证 RecordFailure 原子执行。
type GuardStore interface {
	// RecordFailure 原子记录一次失败，并返回是否达到锁定阈值或已处于锁定。
	RecordFailure(ctx context.Context, key string, at time.Time, policy GuardPolicy) (bool, error)
	// IsLocked 查询主体在指定时刻是否处于锁定状态。
	IsLocked(ctx context.Context, key string, at time.Time) (bool, error)
	// Reset 清除主体的失败计数与锁定状态。
	Reset(ctx context.Context, key string) error
	// Cleanup 清理过期锁定与窗口外失败记录，返回清理项数。
	Cleanup(ctx context.Context, at time.Time, policy GuardPolicy) (int, error)
}

// LoginGuard 登录防爆破守卫（按主体 key 计数与锁定）。
type LoginGuard struct {
	policy     GuardPolicy
	maxEntries int
	store      GuardStore
	now        func() time.Time
}

// Option LoginGuard 配置项。
type Option func(*LoginGuard) error

// WithFailureWindow 设置失败计数窗口（滑动窗口内计数有效）。
func WithFailureWindow(d time.Duration) Option {
	return func(g *LoginGuard) error {
		if d <= 0 {
			return errx.NewCode(authx.CodeSecurityConfigInvalid, "失败窗口必须为正")
		}
		g.policy.FailureWindow = d
		return nil
	}
}

// WithClock 注入时间源（测试用）。
func WithClock(now func() time.Time) Option {
	return func(g *LoginGuard) error {
		if now == nil {
			return errx.NewCode(authx.CodeSecurityConfigInvalid, "时间源不能为空")
		}
		g.now = now
		return nil
	}
}

// WithMaxEntries 设置默认内存存储的条目数量上限。
// 自定义 GuardStore 需自行执行容量控制。
func WithMaxEntries(maxEntries int) Option {
	return func(g *LoginGuard) error {
		if maxEntries <= 0 {
			return errx.NewCode(authx.CodeSecurityConfigInvalid, "条目上限必须为正")
		}
		g.maxEntries = maxEntries
		return nil
	}
}

// WithGuardStore 注入自定义登录守卫存储；未注入时使用进程内内存实现。
func WithGuardStore(store GuardStore) Option {
	return func(g *LoginGuard) error {
		if store == nil {
			return errx.NewCode(authx.CodeSecurityConfigInvalid, "登录守卫存储不能为空")
		}
		g.store = store
		return nil
	}
}

// NewLoginGuard 构造登录守卫。
func NewLoginGuard(maxFailures int, lockDuration time.Duration, opts ...Option) (*LoginGuard, error) {
	if maxFailures <= 0 || lockDuration <= 0 {
		return nil, errx.NewCode(authx.CodeSecurityConfigInvalid, "最大失败次数与锁定时长必须为正")
	}
	g := &LoginGuard{
		policy: GuardPolicy{
			MaxFailures:   maxFailures,
			FailureWindow: 10 * time.Minute,
			LockDuration:  lockDuration,
		},
		maxEntries: defaultMaxEntries,
		now:        time.Now,
	}
	for _, opt := range opts {
		if err := opt(g); err != nil {
			return nil, err
		}
	}
	if g.store == nil {
		g.store = NewMemoryGuardStore(g.maxEntries)
	}
	return g, nil
}

// RecordFailure 记录一次失败；返回 true 表示已达到锁定阈值或已处于锁定。
// 存储故障时按锁定处理，避免降级为无保护登录。
func (g *LoginGuard) RecordFailure(key string) bool {
	locked, err := g.RecordFailureContext(context.Background(), key)
	return err != nil || locked
}

// RecordFailureContext 记录一次失败并返回存储错误。
func (g *LoginGuard) RecordFailureContext(ctx context.Context, key string) (bool, error) {
	return g.store.RecordFailure(ctx, key, g.now(), g.policy)
}

// IsLocked 判断主体当前是否被锁定（过期自动解锁）。
// 存储故障时按锁定处理，避免降级为无保护登录。
func (g *LoginGuard) IsLocked(key string) bool {
	locked, err := g.IsLockedContext(context.Background(), key)
	return err != nil || locked
}

// IsLockedContext 查询主体锁定状态并返回存储错误。
func (g *LoginGuard) IsLockedContext(ctx context.Context, key string) (bool, error) {
	return g.store.IsLocked(ctx, key, g.now())
}

// Reset 清除主体的锁定与失败计数（登录成功后调用）。
func (g *LoginGuard) Reset(key string) {
	_ = g.ResetContext(context.Background(), key)
}

// ResetContext 清除主体的锁定与失败计数并返回存储错误。
func (g *LoginGuard) ResetContext(ctx context.Context, key string) error {
	return g.store.Reset(ctx, key)
}

// Cleanup 清理过期锁定与窗口外失败记录，返回清理项数。
func (g *LoginGuard) Cleanup() int {
	n, _ := g.CleanupContext(context.Background())
	return n
}

// CleanupContext 清理过期状态并返回清理项数与存储错误。
func (g *LoginGuard) CleanupContext(ctx context.Context) (int, error) {
	return g.store.Cleanup(ctx, g.now(), g.policy)
}

// StartCleanup 启动周期性过期清理（间隔必须为正），返回句柄；Stop 停止并等待退出。
// 存储错误会被忽略；需要错误透传时调用 CleanupContext。
func (g *LoginGuard) StartCleanup(interval time.Duration) *authx.CleanupHandle {
	return authx.StartCleanup(interval, func() int {
		n, _ := g.CleanupContext(context.Background())
		return n
	})
}

// MemoryGuardStore 是进程内登录守卫存储；多个 LoginGuard 可共享同一实例。
type MemoryGuardStore struct {
	maxEntries int
	mu         sync.Mutex
	failures   map[string][]time.Time
	locked     map[string]time.Time
}

// NewMemoryGuardStore 构造内存登录守卫存储。
func NewMemoryGuardStore(maxEntries int) *MemoryGuardStore {
	if maxEntries <= 0 {
		panic("authx: 登录守卫容量上限必须为正")
	}
	return &MemoryGuardStore{
		maxEntries: maxEntries,
		failures:   make(map[string][]time.Time),
		locked:     make(map[string]time.Time),
	}
}

// RecordFailure 原子记录失败并判断是否锁定。
func (s *MemoryGuardStore) RecordFailure(
	_ context.Context,
	key string,
	at time.Time,
	policy GuardPolicy,
) (bool, error) {
	if err := validateGuardPolicy(policy); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if until, ok := s.locked[key]; ok && at.Before(until) {
		return true, nil
	}
	if _, exists := s.failures[key]; !exists && len(s.failures)+len(s.locked) >= s.maxEntries {
		// 容量已满且该主体无记录：拒绝记录，防止攻击者用海量 key 撑爆内存。
		return false, nil
	}
	cutoff := at.Add(-policy.FailureWindow)
	kept := s.failures[key][:0]
	for _, t := range s.failures[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, at)
	s.failures[key] = kept
	if len(kept) >= policy.MaxFailures {
		s.locked[key] = at.Add(policy.LockDuration)
		delete(s.failures, key)
		return true, nil
	}
	return false, nil
}

// IsLocked 查询锁定状态并自动清理已到期锁定。
func (s *MemoryGuardStore) IsLocked(_ context.Context, key string, at time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	until, ok := s.locked[key]
	if !ok {
		return false, nil
	}
	if !at.Before(until) {
		delete(s.locked, key)
		return false, nil
	}
	return true, nil
}

// Reset 清除主体的失败计数与锁定状态。
func (s *MemoryGuardStore) Reset(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.locked, key)
	delete(s.failures, key)
	return nil
}

// Cleanup 清理过期锁定与窗口外失败记录。
func (s *MemoryGuardStore) Cleanup(
	_ context.Context,
	at time.Time,
	policy GuardPolicy,
) (int, error) {
	if err := validateGuardPolicy(policy); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for key, until := range s.locked {
		if !at.Before(until) {
			delete(s.locked, key)
			removed++
		}
	}
	cutoff := at.Add(-policy.FailureWindow)
	for key, list := range s.failures {
		kept := list[:0]
		for _, t := range list {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(s.failures, key)
			removed++
		} else {
			s.failures[key] = kept
		}
	}
	return removed, nil
}

func validateGuardPolicy(policy GuardPolicy) error {
	if policy.MaxFailures <= 0 || policy.FailureWindow <= 0 || policy.LockDuration <= 0 {
		return errx.NewCode(authx.CodeSecurityConfigInvalid, "登录守卫策略参数必须为正")
	}
	return nil
}
