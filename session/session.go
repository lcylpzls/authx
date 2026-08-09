// Package session 提供会话数据模型与存储接口（可接 Redis 等外部实现）。
package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/errx"
)

const (
	idBytes           = 32
	createRetry       = 3
	defaultMaxEntries = 100000 // 会话数量上限（防内存无限增长）
)

// randRead 可替换的随机源，便于测试注入失败与冲突场景。
var randRead = rand.Read

// Session 会话数据：ID 与键值对（业务可扩展）。
type Session struct {
	ID     string
	Values map[string]string
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

// sessionItem 内存条目。
type sessionItem struct {
	session Session
	expires time.Time
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
	if ttl <= 0 {
		return Session{}, authx.ErrSessionInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
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
		sess := Session{ID: id, Values: make(map[string]string)}
		s.saveLocked(sess, ttl)
		return sess, nil
	}
	return Session{}, errx.WrapCode(authx.ErrSessionStoreInvalid,
		authx.CodeSessionStoreInvalid, "会话 ID 冲突且重试耗尽")
}

// Get 读取会话。
func (s *MemoryStore) Get(_ context.Context, id string) (Session, error) {
	if id == "" {
		return Session{}, authx.ErrSessionInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[id]
	if !ok {
		return Session{}, authx.ErrSessionNotFound
	}
	if !s.now().Before(item.expires) {
		delete(s.items, id)
		return Session{}, authx.ErrSessionNotFound
	}
	return cloneSession(item.session), nil
}

// Save 保存会话（内部存储副本，避免外部修改）。
func (s *MemoryStore) Save(_ context.Context, sess Session, ttl time.Duration) error {
	if sess.ID == "" || ttl <= 0 {
		return authx.ErrSessionInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[sess.ID]; !ok && len(s.items) >= s.maxEntries {
		return authx.ErrStoreFull
	}
	s.saveLocked(sess, ttl)
	return nil
}

// saveLocked 写入会话（调用方持锁）。
func (s *MemoryStore) saveLocked(sess Session, ttl time.Duration) {
	s.items[sess.ID] = sessionItem{
		session: cloneSession(sess),
		expires: s.now().Add(ttl),
	}
}

// Delete 删除会话。
func (s *MemoryStore) Delete(_ context.Context, id string) error {
	if id == "" {
		return authx.ErrSessionInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, id)
	return nil
}

// Rotate 轮换会话 ID：读取旧会话、生成新 ID、复制全部值并删除旧条目。
func (s *MemoryStore) Rotate(ctx context.Context, id string, ttl time.Duration) (Session, error) {
	if id == "" || ttl <= 0 {
		return Session{}, authx.ErrSessionInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[id]
	if !ok {
		return Session{}, authx.ErrSessionNotFound
	}
	if !s.now().Before(item.expires) {
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
		rotated := Session{ID: nid, Values: make(map[string]string, len(item.session.Values))}
		for k, v := range item.session.Values {
			rotated.Values[k] = v
		}
		s.items[nid] = sessionItem{session: rotated, expires: s.now().Add(ttl)}
		delete(s.items, id)
		return rotated, nil
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
		if !now.Before(item.expires) {
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
	b := make([]byte, idBytes)
	if _, err := randRead(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// cloneSession 深拷贝会话。
func cloneSession(s Session) Session {
	out := Session{ID: s.ID, Values: make(map[string]string, len(s.Values))}
	for k, v := range s.Values {
		out.Values[k] = v
	}
	return out
}
