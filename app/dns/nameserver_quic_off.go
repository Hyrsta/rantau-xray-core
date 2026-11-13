//go:build !xray_doq

package dns

import (
	"net/url"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

// Rantau: DNS over QUIC ("quic+local://" servers) is left out unless built with -tags xray_doq, so the
// DNS app does not link QUIC. A configuration with such a server fails to start instead of skipping it.

// QUICNameServer stands in for the DNS over QUIC client, which is not built in.
type QUICNameServer struct{ Server }

// NewQUICNameServer refuses: DNS over QUIC is not built in.
func NewQUICNameServer(url *url.URL, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP net.IP) (*QUICNameServer, error) {
	return nil, errors.New("DNS over QUIC is not built into this copy of Xray (build with -tags xray_doq): ", url.String())
}
