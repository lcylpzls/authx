package session

import (
	"context"
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
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = store.Get(ctx, sess.ID)
	}
}
