package token_test

import (
	"fmt"
	"time"

	"github.com/lcylpzls/authx/token"
)

// ExampleSigner 演示访问令牌签发与校验。
func ExampleSigner() {
	signer, err := token.NewHS256([]byte("0123456789abcdef0123456789abcdef"),
		token.WithIssuer("myapp"), token.WithTTL(15*time.Minute))
	if err != nil {
		fmt.Println("构造失败：", err)
		return
	}
	raw, err := signer.Sign("u-1001", token.WithRoles("admin"))
	if err != nil {
		fmt.Println("签发失败：", err)
		return
	}
	claims, err := signer.Parse(raw)
	if err != nil {
		fmt.Println("校验失败：", err)
		return
	}
	fmt.Println("主体：", claims.Subject)
	// Output: 主体： u-1001
}
