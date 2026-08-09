package token

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/errx"
)

// TestIssueValidateConsume 覆盖刷新令牌完整生命周期。
func TestIssueValidateConsume(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryRefreshStore(nil)
	raw, err := IssueRefreshToken(ctx, store, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := ValidateRefreshToken(ctx, store, raw)
	if err != nil || !ok {
		t.Fatalf("刷新令牌应有效：ok=%v err=%v", ok, err)
	}
	if err := ConsumeRefreshToken(ctx, store, raw); err != nil {
		t.Fatal(err)
	}
	ok, err = ValidateRefreshToken(ctx, store, raw)
	if err != nil || ok {
		t.Fatalf("消费后刷新令牌应无效：ok=%v err=%v", ok, err)
	}
}

// TestRefreshErrors 覆盖刷新令牌错误分支。
func TestRefreshErrors(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryRefreshStore(nil)
	if _, err := IssueRefreshToken(ctx, nil, time.Hour); err == nil || !errx.Is(err, authx.CodeRefreshTokenInvalid) {
		t.Fatalf("空存储应报错，实际：%v", err)
	}
	orig := randRead
	randRead = func(b []byte) (int, error) { return 0, errors.New("随机源故障") }
	_, err := IssueRefreshToken(ctx, store, time.Hour)
	randRead = orig
	if err == nil || !errx.Is(err, authx.CodeRefreshTokenInvalid) {
		t.Fatalf("随机源故障应报错，实际：%v", err)
	}
	failStore := failingRefreshStore{err: errors.New("存储故障")}
	if _, err := IssueRefreshToken(ctx, failStore, time.Hour); err == nil || !errx.Is(err, authx.CodeRefreshTokenInvalid) {
		t.Fatalf("存储失败应报错，实际：%v", err)
	}
	if _, err := ValidateRefreshToken(ctx, nil, "x"); err == nil {
		t.Fatal("空存储应报错")
	}
	if _, err := ValidateRefreshToken(ctx, store, ""); err == nil {
		t.Fatal("空令牌应报错")
	}
	if _, err := ValidateRefreshToken(ctx, failStore, "x"); err == nil || !errx.Is(err, authx.CodeRefreshTokenInvalid) {
		t.Fatalf("查询失败应报错，实际：%v", err)
	}
	if err := ConsumeRefreshToken(ctx, nil, "x"); err == nil {
		t.Fatal("空存储应报错")
	}
	if err := ConsumeRefreshToken(ctx, store, ""); err == nil {
		t.Fatal("空令牌应报错")
	}
	if err := ConsumeRefreshToken(ctx, failStore, "x"); err == nil || !errx.Is(err, authx.CodeRefreshTokenInvalid) {
		t.Fatalf("删除失败应报错，实际：%v", err)
	}
}

// TestHashRefreshToken 覆盖哈希稳定性。
func TestHashRefreshToken(t *testing.T) {
	const want = "2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b"
	if got := HashRefreshToken("secret"); got != want {
		t.Fatalf("哈希不符：got=%s want=%s", got, want)
	}
}

// failingRefreshStore 返回固定错误的刷新令牌存储。
type failingRefreshStore struct {
	err        error
	validateOK bool
	deleteErr  error
}

func (f failingRefreshStore) Save(context.Context, string, time.Duration) error { return f.err }
func (f failingRefreshStore) Validate(context.Context, string) (bool, error) {
	return f.validateOK, f.err
}
func (f failingRefreshStore) Delete(context.Context, string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	return f.err
}

// TestRotateRefreshToken 覆盖刷新令牌轮换全部分支。
func TestRotateRefreshToken(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryRefreshStore(nil)
	oldRaw, err := IssueRefreshToken(ctx, store, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	newRaw, err := RotateRefreshToken(ctx, store, oldRaw, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if newRaw == oldRaw {
		t.Fatal("轮换后令牌不应相同")
	}
	ok, err := ValidateRefreshToken(ctx, store, oldRaw)
	if err != nil || ok {
		t.Fatalf("旧令牌应失效：ok=%v err=%v", ok, err)
	}
	ok, err = ValidateRefreshToken(ctx, store, newRaw)
	if err != nil || !ok {
		t.Fatalf("新令牌应有效：ok=%v err=%v", ok, err)
	}
	if _, err := RotateRefreshToken(ctx, nil, "x", time.Hour); err == nil ||
		!errx.Is(err, authx.CodeRefreshTokenInvalid) {
		t.Fatalf("空存储应报错，实际：%v", err)
	}
	if _, err := RotateRefreshToken(ctx, store, "", time.Hour); err == nil ||
		!errx.Is(err, authx.CodeRefreshTokenInvalid) {
		t.Fatalf("空令牌应报错，实际：%v", err)
	}
	if _, err := RotateRefreshToken(ctx, store, "not-exist", time.Hour); err == nil ||
		!errx.Is(err, authx.CodeRefreshTokenInvalid) {
		t.Fatalf("无效旧令牌应报错，实际：%v", err)
	}
	failValidate := failingRefreshStore{err: errors.New("查询故障")}
	if _, err := RotateRefreshToken(ctx, failValidate, "x", time.Hour); err == nil ||
		!errx.Is(err, authx.CodeRefreshTokenInvalid) {
		t.Fatalf("查询失败应报错，实际：%v", err)
	}
	failDelete := failingRefreshStore{validateOK: true, deleteErr: errors.New("删除故障")}
	if _, err := RotateRefreshToken(ctx, failDelete, "x", time.Hour); err == nil ||
		!errx.Is(err, authx.CodeRefreshTokenInvalid) {
		t.Fatalf("删除失败应报错，实际：%v", err)
	}
}
