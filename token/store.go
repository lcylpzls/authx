package token

import (
	"context"
	"sync"
	"time"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/errx"
)

// RefreshStore 刷新令牌存储接口（可接入 Redis 等外部实现）。
type RefreshStore interface {
	// Save 保存刷新令牌哈希与过期时间。
	Save(ctx context.Context, hash string, ttl time.Duration) error
	// Validate 判断哈希是否存在且未过期（校验后由业务决定是否 Delete 实现单次使用）。
	Validate(ctx context.Context, hash string) (bool, error)
	// Delete 删除刷新令牌（轮换/登出时调用）。
	Delete(ctx context.Context, hash string) error
}

// RevocationStore 撤销列表存储接口（按 jti 撤销访问令牌）。
type RevocationStore interface {
	// Revoke 撤销指定 jti，保留 ttl 时长。
	Revoke(ctx context.Context, jti string, ttl time.Duration) error
	// IsRevoked 查询 jti 是否已撤销。
	IsRevoked(ctx context.Context, jti string) (bool, error)
}

// memoryItem 内存条目：过期时间。
type memoryItem struct {
	expires time.Time
}

// MemoryRefreshStore 内存刷新令牌存储（进程内，单实例场景）。
type MemoryRefreshStore struct {
	mu    sync.Mutex
	items map[string]memoryItem
	now   func() time.Time
}

// NewMemoryRefreshStore 构造内存刷新令牌存储。
func NewMemoryRefreshStore(now func() time.Time) *MemoryRefreshStore {
	if now == nil {
		now = time.Now
	}
	return &MemoryRefreshStore{items: make(map[string]memoryItem), now: now}
}

// Save 保存刷新令牌哈希。
func (s *MemoryRefreshStore) Save(_ context.Context, hash string, ttl time.Duration) error {
	if hash == "" || ttl <= 0 {
		return errStoreInvalid("刷新令牌哈希与有效期必须合法")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[hash] = memoryItem{expires: s.now().Add(ttl)}
	return nil
}

// Validate 校验哈希存在且未过期。
func (s *MemoryRefreshStore) Validate(_ context.Context, hash string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[hash]
	if !ok {
		return false, nil
	}
	if !s.now().Before(item.expires) {
		delete(s.items, hash)
		return false, nil
	}
	return true, nil
}

// Delete 删除刷新令牌。
func (s *MemoryRefreshStore) Delete(_ context.Context, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, hash)
	return nil
}

// Cleanup 清理全部过期条目，返回清理数量。
func (s *MemoryRefreshStore) Cleanup() int {
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

// MemoryRevocationStore 内存撤销列表。
type MemoryRevocationStore struct {
	mu    sync.Mutex
	items map[string]memoryItem
	now   func() time.Time
}

// NewMemoryRevocationStore 构造内存撤销列表。
func NewMemoryRevocationStore(now func() time.Time) *MemoryRevocationStore {
	if now == nil {
		now = time.Now
	}
	return &MemoryRevocationStore{items: make(map[string]memoryItem), now: now}
}

// Revoke 撤销 jti。
func (s *MemoryRevocationStore) Revoke(_ context.Context, jti string, ttl time.Duration) error {
	if jti == "" || ttl <= 0 {
		return errStoreInvalid("jti 与撤销有效期必须合法")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[jti] = memoryItem{expires: s.now().Add(ttl)}
	return nil
}

// IsRevoked 查询撤销状态（过期条目视为未撤销并清理）。
func (s *MemoryRevocationStore) IsRevoked(_ context.Context, jti string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[jti]
	if !ok {
		return false, nil
	}
	if !s.now().Before(item.expires) {
		delete(s.items, jti)
		return false, nil
	}
	return true, nil
}

// Cleanup 清理过期条目。
func (s *MemoryRevocationStore) Cleanup() int {
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

// errStoreInvalid 构造存储参数错误。
func errStoreInvalid(msg string) error {
	return errx.New(errx.KindInvalid, authx.CodeStoreInvalid, msg)
}
