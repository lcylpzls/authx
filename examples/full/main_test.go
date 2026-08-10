package main

import (
	"testing"

	"github.com/lcylpzls/testx"
)

// TestRun 验证全套示例可完整执行（不依赖外部服务）。
func TestRun(t *testing.T) {
	testx.RequireNoError(t, run())
}
