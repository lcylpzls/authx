package token

import (
	"context"
	"testing"
	"time"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/errx"
)

// TestMemoryRefreshStore 覆盖刷新令牌存储全部路径。
func TestMemoryRefreshStore(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	store := NewMemoryRefreshStore(func() time.Time { return now })
	if err := store.Save(ctx, "", time.Hour); err == nil || !errx.Is(err, authx.CodeStoreInvalid) {
		t.Fatalf("空哈希应报错，实际：%v", err)
	}
	if err := store.Save(ctx, "h", 0); err == nil || !errx.Is(err, authx.CodeStoreInvalid) {
		t.Fatalf("零 TTL 应报错，实际：%v", err)
	}
	if err := store.Save(ctx, "h1", time.Hour); err != nil {
		t.Fatal(err)
	}
	ok, err := store.Validate(ctx, "missing")
	if err != nil || ok {
		t.Fatalf("不存在应返回 false：ok=%v err=%v", ok, err)
	}
	ok, err = store.Validate(ctx, "h1")
	if err != nil || !ok {
		t.Fatalf("有效哈希应为 true：ok=%v err=%v", ok, err)
	}
	if err := store.Save(ctx, "expired", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, "old", time.Hour); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Hour)
	ok, err = store.Validate(ctx, "expired")
	if err != nil || ok {
		t.Fatalf("过期条目应返回 false：ok=%v err=%v", ok, err)
	}
	if err := store.Delete(ctx, "h1"); err != nil {
		t.Fatal(err)
	}
	// "old" 与 "expired" 均在推进时间前保存，推进后已过期；
	// "expired" 已在 Validate 时清理，Cleanup 应再清理 "old"。
	if n := store.Cleanup(); n != 1 {
		t.Fatalf("清理数量应为 1，实际 %d", n)
	}
}

// TestMemoryRevocationStore 覆盖撤销列表全部路径。
func TestMemoryRevocationStore(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	store := NewMemoryRevocationStore(func() time.Time { return now })
	if err := store.Revoke(ctx, "", time.Hour); err == nil || !errx.Is(err, authx.CodeStoreInvalid) {
		t.Fatalf("空 jti 应报错，实际：%v", err)
	}
	if err := store.Revoke(ctx, "j1", 0); err == nil || !errx.Is(err, authx.CodeStoreInvalid) {
		t.Fatalf("零 TTL 应报错，实际：%v", err)
	}
	revoked, err := store.IsRevoked(ctx, "missing")
	if err != nil || revoked {
		t.Fatalf("不存在应返回 false：revoked=%v err=%v", revoked, err)
	}
	if err := store.Revoke(ctx, "j1", time.Hour); err != nil {
		t.Fatal(err)
	}
	revoked, err = store.IsRevoked(ctx, "j1")
	if err != nil || !revoked {
		t.Fatalf("已撤销应为 true：revoked=%v err=%v", revoked, err)
	}
	if err := store.Revoke(ctx, "j2", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke(ctx, "j3", time.Hour); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Hour)
	revoked, err = store.IsRevoked(ctx, "j2")
	if err != nil || revoked {
		t.Fatalf("过期撤销应视为未撤销：revoked=%v err=%v", revoked, err)
	}
	// j1 与 j3 均在推进时间前撤销；推进后两者均已过期，
	// j2 已在 IsRevoked 时清理，Cleanup 应再清理 j1 与 j3。
	if n := store.Cleanup(); n != 2 {
		t.Fatalf("清理数量应为 2，实际 %d", n)
	}
}

// TestMemoryStoresDefaultClock 覆盖默认时间源路径。
func TestMemoryStoresDefaultClock(t *testing.T) {
	ctx := context.Background()
	rs := NewMemoryRefreshStore(nil)
	if err := rs.Save(ctx, "h", time.Minute); err != nil {
		t.Fatal(err)
	}
	ok, err := rs.Validate(ctx, "h")
	if err != nil || !ok {
		t.Fatalf("默认时间源校验失败：ok=%v err=%v", ok, err)
	}
	vs := NewMemoryRevocationStore(nil)
	if err := vs.Revoke(ctx, "j", time.Minute); err != nil {
		t.Fatal(err)
	}
	revoked, err := vs.IsRevoked(ctx, "j")
	if err != nil || !revoked {
		t.Fatalf("默认时间源撤销失败：revoked=%v err=%v", revoked, err)
	}
}
