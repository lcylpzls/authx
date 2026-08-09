package main

import "testing"

// TestRun 验证全套示例可完整执行（不依赖外部服务）。
func TestRun(t *testing.T) {
	if err := run(); err != nil {
		t.Fatalf("示例执行失败：%v", err)
	}
}
