package token

import "github.com/lcylpzls/authx"

// TraceOption 令牌操作链路配置项。
type TraceOption func(*traceConfig)

// traceConfig 令牌操作链路配置。
type traceConfig struct {
	traceHook authx.TraceHook
}

// WithTraceHook 设置链路追踪钩子。
func WithTraceHook(h authx.TraceHook) TraceOption {
	return func(c *traceConfig) { c.traceHook = h }
}

func applyOptions(opts []TraceOption) *traceConfig {
	c := &traceConfig{}
	for _, o := range opts {
		if o != nil {
			o(c)
		}
	}
	return c
}
