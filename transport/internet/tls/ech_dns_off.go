//go:build !xray_ech_dns

package tls

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
)

// Rantau: ECH configs looked up over DNS ("echConfigList" naming a DNS server) are left out unless built
// with -tags xray_ech_dns (ech_dns.go), so the engine does not link a DNS library. The lookup fails, and
// ApplyECH then gives the connection an invalid ECH config, as it does when a lookup fails: the
// connection fails instead of going without ECH. A config given in base64 works as before.
func dnsQuery(server string, domain string, sockopt *internet.SocketConfig) ([]byte, uint32, error) {
	return nil, 0, errors.New("ECH configs over DNS are not built into this copy of Xray (build with -tags xray_ech_dns)")
}
