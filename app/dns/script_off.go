//go:build !xray_lua

package dns

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
)

// Rantau: DNS scripts (Lua) are left out unless built with -tags xray_lua. Lua's reflection makes the
// linker keep every exported method of every type, so it costs more than its own size. A configuration
// with a script fails to start instead of running without it.

type scriptEngine struct{}

func newScriptEngine(string) (*scriptEngine, error) {
	return nil, errors.New("DNS scripts are not built into this copy of Xray (build with -tags xray_lua)")
}

func (*scriptEngine) start(*DNS) error { return nil }

func (*scriptEngine) close() {}

func (*scriptEngine) query(string, dns.IPOption) ([]net.IP, uint32, error) {
	return nil, 0, errors.New("DNS scripts are not built into this copy of Xray")
}
