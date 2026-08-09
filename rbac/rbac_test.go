package rbac

import (
	"testing"

	"github.com/lcylpzls/authx"
	"github.com/lcylpzls/errx"
)

// TestAddRole 覆盖添加角色分支。
func TestAddRole(t *testing.T) {
	r := New()
	if err := r.AddRole(""); err == nil || !errx.Is(err, authx.CodeRBACInvalid) {
		t.Fatalf("空角色名应报错，实际：%v", err)
	}
	if err := r.AddRole("admin", "user:read", ""); err != nil {
		t.Fatal(err)
	}
	if err := r.AddRole("admin"); err == nil || !errx.Is(err, authx.CodeRBACRoleExists) {
		t.Fatalf("重复角色应报错，实际：%v", err)
	}
	if !r.RoleExists("admin") || r.RoleExists("ghost") {
		t.Fatal("RoleExists 判断错误")
	}
}

// TestAddPermission 覆盖追加权限分支。
func TestAddPermission(t *testing.T) {
	r := New()
	if err := r.AddPermission("ghost", "x"); err == nil || !errx.Is(err, authx.CodeRBACRoleNotFound) {
		t.Fatalf("不存在角色应报错，实际：%v", err)
	}
	if err := r.AddRole("admin"); err != nil {
		t.Fatal(err)
	}
	if err := r.AddPermission("admin", "order:read", ""); err != nil {
		t.Fatal(err)
	}
	if !r.HasPermission("admin", "order:read") {
		t.Fatal("权限应已追加")
	}
}

// TestInherit 覆盖继承与环检测。
func TestInherit(t *testing.T) {
	r := New()
	if err := r.Inherit("", "admin"); err == nil || !errx.Is(err, authx.CodeRBACInvalid) {
		t.Fatalf("空角色名应报错，实际：%v", err)
	}
	if err := r.AddRole("admin", "user:read"); err != nil {
		t.Fatal(err)
	}
	if err := r.AddRole("ops", "user:write"); err != nil {
		t.Fatal(err)
	}
	if err := r.AddRole("super"); err != nil {
		t.Fatal(err)
	}
	if err := r.Inherit("super", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := r.Inherit("admin", "super"); err == nil || !errx.Is(err, authx.CodeRBACCycle) {
		t.Fatalf("反向继承应报环，实际：%v", err)
	}
	if err := r.Inherit("admin", "admin"); err == nil || !errx.Is(err, authx.CodeRBACCycle) {
		t.Fatalf("自引用应报环，实际：%v", err)
	}
	if err := r.Inherit("ghost", "admin"); err == nil || !errx.Is(err, authx.CodeRBACRoleNotFound) {
		t.Fatalf("子角色不存在应报错，实际：%v", err)
	}
	if err := r.Inherit("super", "ghost"); err == nil || !errx.Is(err, authx.CodeRBACRoleNotFound) {
		t.Fatalf("父角色不存在应报错，实际：%v", err)
	}
	// 多级继承权限合并。
	if err := r.Inherit("ops", "super"); err != nil {
		t.Fatal(err)
	}
	perms := r.PermissionsOf("ops")
	if _, ok := perms["user:read"]; !ok {
		t.Fatal("ops 应继承 admin 权限")
	}
	if _, ok := perms["user:write"]; !ok {
		t.Fatal("ops 应保留自身权限")
	}
	if !r.HasPermission("ops", "user:read") {
		t.Fatal("HasPermission 应识别继承权限")
	}
	if len(r.PermissionsOf("ghost")) != 0 {
		t.Fatal("不存在角色应返回空权限")
	}
}

// TestHasPermission 覆盖权限判断分支。
func TestHasPermission(t *testing.T) {
	r := New()
	if r.HasPermission("ghost", "x") {
		t.Fatal("不存在角色不应有权限")
	}
	if err := r.AddRole("user", "a", "b"); err != nil {
		t.Fatal(err)
	}
	if !r.HasPermission("user", "a") {
		t.Fatal("直接权限应命中")
	}
	if r.HasPermission("user", "c") {
		t.Fatal("未授权权限不应命中")
	}
}

// TestHasAnyAll 覆盖批量权限判断。
func TestHasAnyAll(t *testing.T) {
	r := New()
	if err := r.AddRole("user", "a", "b"); err != nil {
		t.Fatal(err)
	}
	if r.HasAnyPermission(nil, "a") {
		t.Fatal("空角色不应命中")
	}
	if !r.HasAnyPermission([]string{"user"}, "a") {
		t.Fatal("HasAny 应命中")
	}
	if r.HasAnyPermission([]string{"user"}, "c") {
		t.Fatal("HasAny 不应命中未授权权限")
	}
	if r.HasAllPermissions([]string{"user"}) {
		t.Fatal("空权限集不应命中")
	}
	if r.HasAllPermissions([]string{"user"}, "a", "c") {
		t.Fatal("缺权限应失败")
	}
	if !r.HasAllPermissions([]string{"user"}, "a", "b") {
		t.Fatal("全部权限应命中")
	}
}

// TestCycleVisited 直接构造已损坏的环，覆盖环检测的 visited 分支。
func TestCycleVisited(t *testing.T) {
	r := New()
	_ = r.AddRole("a")
	_ = r.AddRole("b")
	r.roles["a"].parents = []string{"b"}
	r.roles["b"].parents = []string{"a"}
	if !r.createsCycleLocked("a", "b") {
		t.Fatal("已存在的环应被检测到")
	}
	// 走完 visited 防重复路径后继续遍历其余节点。
	_ = r.AddRole("c")
	r.roles["b"].parents = []string{"a", "c"}
	if !r.createsCycleLocked("a", "c") {
		t.Fatal("重复访问节点后仍应检测到可达目标")
	}
}

// TestNewWithLimitsPanic 覆盖非法规模上限 panic。
func TestNewWithLimitsPanic(t *testing.T) {
	for _, args := range [][2]int{{0, 10}, {10, 0}} {
		func(a, b int) {
			defer func() {
				if r := recover(); r == nil {
					t.Error("非正上限应 panic")
				}
			}()
			NewWithLimits(a, b)
		}(args[0], args[1])
	}
}

// TestMaxRoles 覆盖角色数量上限。
func TestMaxRoles(t *testing.T) {
	r := NewWithLimits(2, 10)
	if err := r.AddRole("a"); err != nil {
		t.Fatal(err)
	}
	if err := r.AddRole("b"); err != nil {
		t.Fatal(err)
	}
	if err := r.AddRole("c"); err == nil || !errx.Is(err, authx.CodeRBACLimit) {
		t.Fatalf("角色数量超限应报错，实际：%v", err)
	}
}

// TestMaxDepth 覆盖继承深度上限。
func TestMaxDepth(t *testing.T) {
	r := NewWithLimits(10, 3)
	for _, name := range []string{"a", "b", "c", "d"} {
		if err := r.AddRole(name); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Inherit("b", "a"); err != nil {
		t.Fatal(err)
	}
	if err := r.Inherit("c", "b"); err != nil {
		t.Fatal(err)
	}
	if err := r.Inherit("d", "c"); err == nil || !errx.Is(err, authx.CodeRBACLimit) {
		t.Fatalf("继承深度超限应报错，实际：%v", err)
	}
}

// TestDepthVisited 直接构造已损坏的环，覆盖深度计算的 visited 分支。
func TestDepthVisited(t *testing.T) {
	r := New()
	_ = r.AddRole("a")
	_ = r.AddRole("b")
	r.roles["a"].parents = []string{"b"}
	r.roles["b"].parents = []string{"a"}
	if got := r.depthOfLocked("a"); got == 0 {
		t.Fatal("环内深度计算不应返回零")
	}
}
