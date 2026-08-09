package session_test

import (
	"context"
	"fmt"
	"time"

	"github.com/lcylpzls/authx/session"
)

// ExampleMemoryStore 演示会话创建、保存与读取。
func ExampleMemoryStore() {
	store := session.NewMemoryStore(nil)
	ctx := context.Background()
	sess, err := store.Create(ctx, time.Hour)
	if err != nil {
		fmt.Println("创建失败：", err)
		return
	}
	sess.Values["uid"] = "u-1001"
	if err := store.Save(ctx, sess, time.Hour); err != nil {
		fmt.Println("保存失败：", err)
		return
	}
	got, err := store.Get(ctx, sess.ID)
	if err != nil {
		fmt.Println("读取失败：", err)
		return
	}
	fmt.Println("会话值：", got.Values["uid"])
	// Output: 会话值： u-1001
}
