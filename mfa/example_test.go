package mfa_test

import (
	"fmt"
	"time"

	"github.com/lcylpzls/authx/mfa"
)

// ExampleGenerateCode 演示 TOTP 密钥生成、验证码生成与校验。
func ExampleGenerateCode() {
	secret, err := mfa.GenerateSecret()
	if err != nil {
		fmt.Println("密钥生成失败：", err)
		return
	}
	at := time.Now()
	code, err := mfa.GenerateCode(secret, at)
	if err != nil {
		fmt.Println("验证码生成失败：", err)
		return
	}
	ok, err := mfa.ValidateCode(secret, code, at, 1)
	if err != nil || !ok {
		fmt.Println("校验失败：", err)
		return
	}
	fmt.Println("TOTP 校验通过")
	// Output: TOTP 校验通过
}
