package oauth2

import (
	"net/http"
)

// oauth2UserHandler 适配 go-oauth2 的用户解析器：从请求上下文读取登录态。
func (s *Server) oauth2UserHandler(w http.ResponseWriter, r *http.Request) (string, error) {
	id, _ := UserIDFromContext(r.Context())
	return id, nil
}

// SetUserAuthorizationHandlerFromContext 便捷入口：内部固定从请求上下文解析用户。
// 业务统一使用 WithUserID 写入登录态，无需自定义解析器。
func (s *Server) SetUserAuthorizationHandlerFromContext() {
	s.contextAuth = true
	s.inner.SetUserAuthorizationHandler(s.oauth2UserHandler)
}
