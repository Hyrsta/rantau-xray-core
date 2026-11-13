//go:build !xray_lua

package router

import (
	"context"
	"testing"
)

// Without the xray_lua tag a configuration that asks for a routing script must fail to start, not route without it.
func TestScriptNeedsTheLuaTag(t *testing.T) {
	r := new(Router)
	if err := r.Init(context.Background(), &Config{Script: "route.lua"}, nil, nil, nil); err == nil {
		t.Fatal("Init with a script succeeded; want an error")
	}
	if r.script != nil {
		t.Fatal("the router kept a script engine")
	}
}
