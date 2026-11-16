// Package session 提供会话数据模型与存储接口（可接 Redis 等外部实现）。
package session

import (
	"context"
	"sync"
	"time"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/errx"
	"github.com/lcylpzls/idgenx"
	"github.com/lcylpzls/validx"
)

const (
	idBytes           = 32
	createRetry       = 3
	defaultMaxEntries = 100000 // 会话数量上限（防内存无限增长）
)

// randRead 可替换的随机源，便于测试注入失败与冲突场景。
var randRead = idgenx.RandomHex

// validSessionArg 使用 validx 规则校验会话参数，失败返回 ErrSessionInvalid。
func validSessionArg(value any, rules string) error {
	if err := validx.ValidateField(value, rules); err != nil {
		return authx.ErrSessionInvalid
	}
	return nil
}

// Session 会话数据：ID、键值对与存储无关的期限元数据。
type Session struct {
	ID                string
	Values            map[string]string
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
}

// Lifetime 描述会话的空闲期限与绝对期限；AbsoluteTTL 为 0 表示不设绝对期限。
type Lifetime struct {
	IdleTTL     time.Duration
	AbsoluteTTL time.Duration
}

// Store 会话存储接口。
type Store interface {
	// Create 创建并保存新会话（自动生成 ID），返回会话。
	Create(ctx context.Context, ttl time.Duration) (Session, error)
	// Get 读取会话；不存在或已过期返回 ErrSessionNotFound。
	Get(ctx context.Context, id string) (Session, error)
	// Save 保存会话（中间件在请求结束后自动调用）。
	Save(ctx context.Context, s Session, ttl time.Duration) error
	// Delete 删除会话（登出时调用）。
	Delete(ctx context.Context, id string) error
	// Rotate 将指定会话轮换为新随机 ID 并保留全部值，删除旧条目
	// （防会话固定攻击；不存在或已过期返回 ErrSessionNotFound）。
	Rotate(ctx context.Context, id string, ttl time.Duration) (Session, error)
}

// ExpiryStore 是可选的会话期限存储扩展。
// 需要使用绝对期限时，自定义 Store 必须同时实现该接口。
type ExpiryStore interface {
	// CreateWithLifetime 创建会话并同时保存空闲与绝对期限。
	CreateWithLifetime(ctx context.Context, lifetime Lifetime) (Session, error)
	// SaveWithLifetime 保存会话；已有绝对期限不能被后续保存延长。
	SaveWithLifetime(ctx context.Context, s Session, lifetime Lifetime) error
	// RotateWithLifetime 轮换 ID、保留绝对期限并重置空闲期限。
	RotateWithLifetime(ctx context.Context, id string, lifetime Lifetime) (Session, error)
}

// sessionItem 内存条目。
type sessionItem struct {
	session Session
}

// MemoryStore 内存会话存储（进程内单实例场景）。
type MemoryStore struct {
	mu         sync.Mutex
	items      map[string]sessionItem
	now        func() time.Time
	maxEntries int
}

// NewMemoryStore 构造内存会话存储。
func NewMemoryStore(now func() time.Time) *MemoryStore {
	return NewMemoryStoreWithLimit(now, defaultMaxEntries)
}

// NewMemoryStoreWithLimit 构造带容量上限的内存会话存储。
// maxEntries 必须为正，否则 panic（配置错误应尽早暴露）。
func NewMemoryStoreWithLimit(now func() time.Time, maxEntries int) *MemoryStore {
	if maxEntries <= 0 {
		panic("authx: 会话存储容量上限必须为正")
	}
	if now == nil {
		now = time.Now
	}
	return &MemoryStore{items: make(map[string]sessionItem), now: now, maxEntries: maxEntries}
}

// Create 创建并保存新会话。
func (s *MemoryStore) Create(ctx context.Context, ttl time.Duration) (Session, error) {
	return s.CreateWithLifetime(ctx, Lifetime{IdleTTL: ttl})
}

// CreateWithLifetime 创建并保存带空闲与绝对期限的新会话。
func (s *MemoryStore) CreateWithLifetime(ctx context.Context, lifetime Lifetime) (Session, error) {
	if err := validateLifetime(lifetime); err != nil {
		return Session{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for attempt := 0; attempt < createRetry; attempt++ {
		id, err := newSessionID()
		if err != nil {
			return Session{}, errx.WrapCode(err, authx.CodeSessionStoreInvalid, "会话 ID 生成失败")
		}
		if _, ok := s.items[id]; ok {
			continue // ID 冲突，重试。
		}
		if len(s.items) >= s.maxEntries {
			return Session{}, authx.ErrStoreFull
		}
		sess := Session{
			ID:                id,
			Values:            make(map[string]string),
			IdleExpiresAt:     nextExpiry(now, lifetime.IdleTTL),
			AbsoluteExpiresAt: nextExpiry(now, lifetime.AbsoluteTTL),
		}
		s.items[id] = sessionItem{session: cloneSession(sess)}
		return cloneSession(sess), nil
	}
	return Session{}, errx.WrapCode(authx.ErrSessionStoreInvalid,
		authx.CodeSessionStoreInvalid, "会话 ID 冲突且重试耗尽")
}

// Get 读取会话。
func (s *MemoryStore) Get(_ context.Context, id string) (Session, error) {
	if err := validSessionArg(id, "required"); err != nil {
		return Session{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[id]
	if !ok {
		return Session{}, authx.ErrSessionNotFound
	}
	if expired(item.session, s.now()) {
		delete(s.items, id)
		return Session{}, authx.ErrSessionNotFound
	}
	return cloneSession(item.session), nil
}

// Save 保存会话（内部存储副本，避免外部修改）。
func (s *MemoryStore) Save(ctx context.Context, sess Session, ttl time.Duration) error {
	return s.SaveWithLifetime(ctx, sess, Lifetime{IdleTTL: ttl})
}

// SaveWithLifetime 保存会话并刷新空闲期限；已有绝对期限保持不变。
func (s *MemoryStore) SaveWithLifetime(_ context.Context, sess Session, lifetime Lifetime) error {
	if err := validSessionArg(sess.ID, "required"); err != nil {
		return err
	}
	if err := validateLifetime(lifetime); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if item, ok := s.items[sess.ID]; ok && !item.session.AbsoluteExpiresAt.IsZero() {
		if sess.AbsoluteExpiresAt.IsZero() ||
			item.session.AbsoluteExpiresAt.Before(sess.AbsoluteExpiresAt) {
			sess.AbsoluteExpiresAt = item.session.AbsoluteExpiresAt
		}
	}
	if sess.AbsoluteExpiresAt.IsZero() && lifetime.AbsoluteTTL > 0 {
		sess.AbsoluteExpiresAt = nextExpiry(now, lifetime.AbsoluteTTL)
	}
	if _, ok := s.items[sess.ID]; !ok && len(s.items) >= s.maxEntries {
		return authx.ErrStoreFull
	}
	sess.IdleExpiresAt = nextExpiry(now, lifetime.IdleTTL)
	s.items[sess.ID] = sessionItem{session: cloneSession(sess)}
	return nil
}

// Delete 删除会话。
func (s *MemoryStore) Delete(_ context.Context, id string) error {
	if err := validSessionArg(id, "required"); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, id)
	return nil
}

// Rotate 轮换会话 ID：读取旧会话、生成新 ID、复制全部值并删除旧条目。
func (s *MemoryStore) Rotate(ctx context.Context, id string, ttl time.Duration) (Session, error) {
	return s.RotateWithLifetime(ctx, id, Lifetime{IdleTTL: ttl})
}

// RotateWithLifetime 轮换会话 ID：保留绝对期限，刷新空闲期限并复制全部值。
func (s *MemoryStore) RotateWithLifetime(
	ctx context.Context,
	id string,
	lifetime Lifetime,
) (Session, error) {
	if err := validSessionArg(id, "required"); err != nil {
		return Session{}, err
	}
	if err := validateLifetime(lifetime); err != nil {
		return Session{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[id]
	if !ok {
		return Session{}, authx.ErrSessionNotFound
	}
	now := s.now()
	if expired(item.session, now) {
		delete(s.items, id)
		return Session{}, authx.ErrSessionNotFound
	}
	for attempt := 0; attempt < createRetry; attempt++ {
		nid, err := newSessionID()
		if err != nil {
			return Session{}, errx.WrapCode(err, authx.CodeSessionStoreInvalid, "会话 ID 生成失败")
		}
		if _, exists := s.items[nid]; exists {
			continue // ID 冲突，重试。
		}
		rotated := Session{
			ID:                nid,
			Values:            make(map[string]string, len(item.session.Values)),
			IdleExpiresAt:     nextExpiry(now, lifetime.IdleTTL),
			AbsoluteExpiresAt: item.session.AbsoluteExpiresAt,
		}
		for k, v := range item.session.Values {
			rotated.Values[k] = v
		}
		if rotated.AbsoluteExpiresAt.IsZero() && lifetime.AbsoluteTTL > 0 {
			rotated.AbsoluteExpiresAt = nextExpiry(now, lifetime.AbsoluteTTL)
		}
		s.items[nid] = sessionItem{session: cloneSession(rotated)}
		delete(s.items, id)
		return cloneSession(rotated), nil
	}
	return Session{}, errx.WrapCode(authx.ErrSessionStoreInvalid,
		authx.CodeSessionStoreInvalid, "会话 ID 冲突且重试耗尽")
}

// Cleanup 清理过期会话，返回清理数量。
func (s *MemoryStore) Cleanup() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	removed := 0
	for id, item := range s.items {
		if expired(item.session, now) {
			delete(s.items, id)
			removed++
		}
	}
	return removed
}

// StartCleanup 启动周期性过期清理（间隔必须为正），返回句柄；Stop 停止并等待退出。
func (s *MemoryStore) StartCleanup(interval time.Duration) *authx.CleanupHandle {
	return authx.StartCleanup(interval, s.Cleanup)
}

// newSessionID 生成 32 字节随机十六进制会话 ID。
func newSessionID() (string, error) {
	return randRead(idBytes)
}

func validateLifetime(lifetime Lifetime) error {
	if lifetime.IdleTTL <= 0 || lifetime.AbsoluteTTL < 0 {
		return authx.ErrSessionInvalid
	}
	return nil
}

func nextExpiry(now time.Time, ttl time.Duration) time.Time {
	if ttl <= 0 {
		return time.Time{}
	}
	return now.Add(ttl)
}

func expired(sess Session, now time.Time) bool {
	return (!sess.IdleExpiresAt.IsZero() && !now.Before(sess.IdleExpiresAt)) ||
		(!sess.AbsoluteExpiresAt.IsZero() && !now.Before(sess.AbsoluteExpiresAt))
}

// cloneSession 深拷贝会话。
func cloneSession(s Session) Session {
	out := Session{
		ID:                s.ID,
		Values:            make(map[string]string, len(s.Values)),
		IdleExpiresAt:     s.IdleExpiresAt,
		AbsoluteExpiresAt: s.AbsoluteExpiresAt,
	}
	for k, v := range s.Values {
		out.Values[k] = v
	}
	return out
}
