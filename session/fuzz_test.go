package session

import (
	"context"
	"strings"
	"testing"
	"time"
)

// FuzzSessionStore 模糊测试会话存储操作序列，确保任意输入不 panic。
func FuzzSessionStore(f *testing.F) {
	f.Add([]byte("c;g:abc;s:abc:xyz;r:abc;d:abc"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			t.Skip("输入过大")
		}
		store := NewMemoryStoreWithLimit(func() time.Time { return time.Now() }, 128)
		ctx := context.Background()
		for _, op := range strings.Split(string(data), ";") {
			if op == "" {
				continue
			}
			switch op[0] {
			case 'c':
				_, _ = store.Create(ctx, time.Hour)
			case 'g':
				_, _ = store.Get(ctx, strings.TrimPrefix(op, "g:"))
			case 's':
				seg := strings.SplitN(strings.TrimPrefix(op, "s:"), ":", 2)
				if len(seg) == 2 {
					_ = store.Save(ctx, Session{ID: seg[0], Values: map[string]string{"k": seg[1]}}, time.Hour)
				}
			case 'd':
				_ = store.Delete(ctx, strings.TrimPrefix(op, "d:"))
			case 'r':
				_, _ = store.Rotate(ctx, strings.TrimPrefix(op, "r:"), time.Hour)
			}
		}
		_ = store.Cleanup()
	})
}
