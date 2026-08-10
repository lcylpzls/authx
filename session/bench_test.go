package session

import (
	"context"
	testx "github.com/lcylpzls/testx"
	"testing"
	"time"
)

// BenchmarkStoreSave 测量会话保存耗时。
func BenchmarkStoreSave(b *testing.B) {
	store := NewMemoryStore(nil)
	ctx := context.Background()
	sess := Session{ID: "s-1", Values: map[string]string{"k": "v"}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = store.Save(ctx, sess, time.Hour)
	}
}

// BenchmarkStoreGet 测量会话读取耗时。
func BenchmarkStoreGet(b *testing.B) {
	store := NewMemoryStore(nil)
	ctx := context.Background()
	sess, err := store.Create(ctx, time.Hour)
	testx.RequireNoError(b, err)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = store.Get(ctx, sess.ID)
	}
}

// BenchmarkStoreConcurrent 测量高并发会话读写。
func BenchmarkStoreConcurrent(b *testing.B) {
	store := NewMemoryStore(nil)
	ctx := context.Background()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			sess, err := store.Create(ctx, time.Hour)
			if err != nil {
				continue
			}
			_, _ = store.Get(ctx, sess.ID)
			_ = store.Delete(ctx, sess.ID)
		}
	})
}
