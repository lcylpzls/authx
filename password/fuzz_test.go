package password

import (
	"strings"
	"testing"

	"github.com/lcylpzls/authx"
)

// FuzzVerify 保证任意输入下 Verify/NeedsRehash 不 panic。
func FuzzVerify(f *testing.F) {
	h, err := Hash("password123", authx.DefaultPasswordConfig())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(h, "password123")
	f.Add("$argon2id$v=19$m=32,t=3,p=4$AgICAgICAgICAgICAgI$DWRHDXh2dmwIwDejSotTydAe8EItdbZetSUg6WsB5lk", "x")
	f.Add("", "")
	f.Add(strings.Repeat("a", 2048), "short")
	f.Fuzz(func(t *testing.T, hash, plain string) {
		_, _ = Verify(hash, plain)
		_, _ = NeedsRehash(hash, authx.DefaultPasswordConfig())
	})
}
