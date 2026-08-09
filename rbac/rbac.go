// Package rbac 提供轻量角色-权限模型，支持角色继承与并发安全。
package rbac

import (
	"sync"

	"github.com/lcylpzls/authx"
)

const (
	defaultMaxRoles = 10000 // 角色数量上限（防内存无限增长）
	defaultMaxDepth = 32    // 角色继承链深度上限（防极端链导致递归过深）
)

// RBAC 角色-权限存储（读写并发安全）。
type RBAC struct {
	mu       sync.RWMutex
	roles    map[string]*role
	maxRoles int
	maxDepth int
}

// role 单个角色定义。
type role struct {
	name        string
	permissions map[string]struct{}
	parents     []string
}

// New 构造空 RBAC。
func New() *RBAC {
	return NewWithLimits(defaultMaxRoles, defaultMaxDepth)
}

// NewWithLimits 构造带规模上限的 RBAC。
// maxRoles 与 maxDepth 必须为正，否则 panic（配置错误应尽早暴露）。
func NewWithLimits(maxRoles, maxDepth int) *RBAC {
	if maxRoles <= 0 || maxDepth <= 0 {
		panic("authx: RBAC 规模上限必须为正")
	}
	return &RBAC{roles: make(map[string]*role), maxRoles: maxRoles, maxDepth: maxDepth}
}

// AddRole 添加角色及初始权限；空角色名或已存在角色返回错误。
func (r *RBAC) AddRole(name string, permissions ...string) error {
	if name == "" {
		return authx.ErrRBACInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.roles[name]; ok {
		return authx.ErrRoleExists
	}
	if len(r.roles) >= r.maxRoles {
		return authx.ErrRBACLimit
	}
	rl := &role{name: name, permissions: make(map[string]struct{})}
	for _, p := range permissions {
		if p != "" {
			rl.permissions[p] = struct{}{}
		}
	}
	r.roles[name] = rl
	return nil
}

// AddPermission 为角色追加权限；角色不存在返回错误。
func (r *RBAC) AddPermission(name string, permissions ...string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rl, ok := r.roles[name]
	if !ok {
		return authx.ErrRoleNotFound
	}
	for _, p := range permissions {
		if p != "" {
			rl.permissions[p] = struct{}{}
		}
	}
	return nil
}

// Inherit 让角色继承另一个角色的权限；任一角色不存在、自引用或形成环返回错误。
func (r *RBAC) Inherit(name, parent string) error {
	if name == "" || parent == "" {
		return authx.ErrRBACInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if name == parent {
		return authx.ErrCycle
	}
	rl, ok := r.roles[name]
	if !ok {
		return authx.ErrRoleNotFound
	}
	if _, ok := r.roles[parent]; !ok {
		return authx.ErrRoleNotFound
	}
	if r.createsCycleLocked(parent, name) {
		return authx.ErrCycle
	}
	if r.depthOfLocked(parent)+1 > r.maxDepth {
		return authx.ErrRBACLimit
	}
	rl.parents = append(rl.parents, parent)
	return nil
}

// depthOfLocked 返回角色的最大继承链深度（自身为 1，调用方持读锁）。
func (r *RBAC) depthOfLocked(name string) int {
	visited := make(map[string]bool)
	var depth func(string) int
	depth = func(current string) int {
		if visited[current] {
			return 0 // 环已在 Inherit 中拦截，此处仅防御。
		}
		visited[current] = true
		best := 0
		for _, p := range r.roles[current].parents {
			if d := depth(p); d > best {
				best = d
			}
		}
		return best + 1
	}
	return depth(name)
}

// createsCycleLocked 检查 parent 的祖先链是否包含 name（含未上锁调用约定）。
func (r *RBAC) createsCycleLocked(start, target string) bool {
	visited := make(map[string]bool)
	var walk func(string) bool
	walk = func(current string) bool {
		if current == target {
			return true
		}
		if visited[current] {
			return false
		}
		visited[current] = true
		for _, p := range r.roles[current].parents {
			if walk(p) {
				return true
			}
		}
		return false
	}
	return walk(start)
}

// RoleExists 判断角色是否存在。
func (r *RBAC) RoleExists(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.roles[name]
	return ok
}

// HasPermission 判断角色（含继承）是否具备权限。
func (r *RBAC) HasPermission(name, permission string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if _, ok := r.roles[name]; !ok {
		return false
	}
	perms := r.permissionsOfLocked(name, make(map[string]bool))
	_, ok := perms[permission]
	return ok
}

// HasAnyPermission 判断任意给定角色具备任意给定权限。
func (r *RBAC) HasAnyPermission(names []string, permissions ...string) bool {
	for _, name := range names {
		for _, p := range permissions {
			if r.HasPermission(name, p) {
				return true
			}
		}
	}
	return false
}

// HasAllPermissions 判断任意给定角色同时具备全部给定权限。
func (r *RBAC) HasAllPermissions(names []string, permissions ...string) bool {
	if len(permissions) == 0 {
		return false
	}
	merged := make(map[string]struct{})
	for _, name := range names {
		for p := range r.PermissionsOf(name) {
			merged[p] = struct{}{}
		}
	}
	for _, p := range permissions {
		if _, ok := merged[p]; !ok {
			return false
		}
	}
	return true
}

// PermissionsOf 返回角色（含全部祖先）的权限集合副本。
func (r *RBAC) PermissionsOf(name string) map[string]struct{} {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.permissionsOfLocked(name, make(map[string]bool))
}

// permissionsOfLocked 递归合并角色与祖先权限（调用方持读锁）。
func (r *RBAC) permissionsOfLocked(name string, visited map[string]bool) map[string]struct{} {
	out := make(map[string]struct{})
	rl, ok := r.roles[name]
	if !ok || visited[name] {
		return out
	}
	visited[name] = true
	for p := range rl.permissions {
		out[p] = struct{}{}
	}
	for _, parent := range rl.parents {
		for p := range r.permissionsOfLocked(parent, visited) {
			out[p] = struct{}{}
		}
	}
	return out
}
