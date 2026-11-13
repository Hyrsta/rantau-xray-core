//go:build !xray_lua

package dns

import (
	"context"
	"testing"
)

// Without the xray_lua tag a configuration that asks for a DNS script must fail to start, not run without it.
func TestScriptNeedsTheLuaTag(t *testing.T) {
	if server, err := New(context.Background(), &Config{Script: "dns.lua"}); err == nil || server != nil {
		t.Fatalf("New with a script: %v, %v; want an error", server, err)
	}
	if _, err := New(context.Background(), &Config{}); err != nil {
		t.Fatalf("New without a script: %v", err)
	}
}
