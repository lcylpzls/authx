package oauth2

import (
	"net/http"

	"github.com/lcylpzls/webx/v2"
)

// AuthorizeWebxHandler 返回 webx 适配的 /authorize 处理器。
// 业务认证中间件需先调用 WithUserID 将登录态写入请求上下文。
func (s *Server) AuthorizeWebxHandler() webx.HandlerFunc {
	return func(c *webx.Context) {
		if _, ok := UserIDFromContext(c.Request().Context()); !ok {
			writeUnauthorized(c.Writer(), "用户未登录")
			return
		}
		_ = s.inner.HandleAuthorizeRequest(c.Writer(), c.Request())
	}
}

// TokenWebxHandler 返回 webx 适配的 /token 处理器。
func (s *Server) TokenWebxHandler() webx.HandlerFunc {
	return func(c *webx.Context) {
		// 库内错误已写 JSON 错误响应，无需二次处理。
		_ = s.inner.HandleTokenRequest(c.Writer(), c.Request())
	}
}

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
