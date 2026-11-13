//go:build !xray_lua

package router

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/features/routing"
)

// Rantau: routing scripts (Lua) are left out unless built with -tags xray_lua (see app/dns/script_off.go).
// A configuration with a script fails to start instead of routing without it.

type scriptEngine struct{}

func newScriptEngine(string) (*scriptEngine, error) {
	return nil, errors.New("routing scripts are not built into this copy of Xray (build with -tags xray_lua)")
}

func (*scriptEngine) start(*Router) error { return nil }

func (*scriptEngine) close() {}

func (*scriptEngine) pickRoute(routing.Context) (routing.Route, error) {
	return nil, errors.New("routing scripts are not built into this copy of Xray")
}
