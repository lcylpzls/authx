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
	idBytes     = 32
	createRetry = 3
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
}

// sessionItem 内存条目。
type sessionItem struct {
	session Session
	expires time.Time
}

// MemoryStore 内存会话存储（进程内单实例场景）。
type MemoryStore struct {
	mu    sync.Mutex
	items map[string]sessionItem
	now   func() time.Time
}

// NewMemoryStore 构造内存会话存储。
func NewMemoryStore(now func() time.Time) *MemoryStore {
	if now == nil {
		now = time.Now
	}
	return &MemoryStore{items: make(map[string]sessionItem), now: now}
}

// Create 创建并保存新会话。
func (s *MemoryStore) Create(ctx context.Context, ttl time.Duration) (Session, error) {
	if ttl <= 0 {
		return Session{}, authx.ErrSessionInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for attempt := 0; attempt < createRetry; attempt++ {
		id := newSessionID()
		if _, ok := s.items[id]; ok {
			continue // ID 冲突，重试。
		}
		sess := Session{ID: id, Values: make(map[string]string)}
		s.saveLocked(sess, ttl)
		return sess, nil
	}
	return Session{}, errx.Wrap(authx.ErrSessionStoreInvalid, errx.KindUnavailable,
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

// newSessionID 生成 32 字节随机十六进制会话 ID。
func newSessionID() string {
	b := make([]byte, idBytes)
	if _, err := randRead(b); err != nil {
		// 随机源故障时回退到时间戳（唯一性降低，仅测试/故障兜底）。
		return hex.EncodeToString([]byte(time.Now().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(b)
}

// cloneSession 深拷贝会话。
func cloneSession(s Session) Session {
	out := Session{ID: s.ID, Values: make(map[string]string, len(s.Values))}
	for k, v := range s.Values {
		out.Values[k] = v
	}
	return out
}
