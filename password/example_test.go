package password_test

import (
	"fmt"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/authx/password"
)

// ExampleHash 演示密码哈希、校验与参数迁移。
func ExampleHash() {
	cfg := authx.DefaultPasswordConfig()
	hash, err := password.Hash("password123", cfg)
	if err != nil {
		fmt.Println("哈希失败：", err)
		return
	}
	ok, err := password.Verify(hash, "password123")
	if err != nil || !ok {
		fmt.Println("校验失败：", err)
		return
	}
	need, err := password.NeedsRehash(hash, cfg)
	if err != nil {
		fmt.Println("迁移检测失败：", err)
		return
	}
	fmt.Println("校验通过；需要迁移：", need)
	// Output: 校验通过；需要迁移： false
}
