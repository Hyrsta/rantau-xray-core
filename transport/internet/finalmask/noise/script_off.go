//go:build !xray_lua

package noise

import (
	"time"

	"github.com/xtls/xray-core/common/errors"
)

// Rantau: noise scripts (Lua) are left out unless built with -tags xray_lua (see app/dns/script_off.go).
// A mask with a script fails to start instead of sending no noise.

type scriptEngine struct{}

type scriptPacket struct {
	packet []byte
	delay  time.Duration
}

func (c *Config) engine() (*scriptEngine, error) {
	return nil, errors.New("noise scripts are not built into this copy of Xray (build with -tags xray_lua)")
}

func (*scriptEngine) packets(string, []scriptPacket) ([]scriptPacket, error) {
	return nil, errors.New("noise scripts are not built into this copy of Xray")
}
