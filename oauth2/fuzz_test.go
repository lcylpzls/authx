package oauth2

import (
	"testing"
)

// FuzzOAuth2Config 模糊测试客户端与服务端配置校验，确保任意输入不 panic。
func FuzzOAuth2Config(f *testing.F) {
	f.Add("id", "secret", "https://a/auth", "https://a/token", "https://a/cb", "https://a/userinfo")
	f.Fuzz(func(t *testing.T, clientID, secret, authURL, tokenURL, redirect, userInfo string) {
		if len(clientID) > 256 || len(secret) > 256 || len(authURL) > 1024 ||
			len(tokenURL) > 1024 || len(redirect) > 1024 || len(userInfo) > 1024 {
			t.Skip("输入过大")
		}
		_, _ = NewClient(ProviderConfig{
			ClientID:     clientID,
			ClientSecret: secret,
			AuthURL:      authURL,
			TokenURL:     tokenURL,
			RedirectURL:  redirect,
			UserInfoURL:  userInfo,
		})
		_, _ = NewServer(ServerConfig{ClientID: clientID, ClientSecret: secret, RedirectURL: redirect})
	})
}
