//go:build !xray_doq

package dns

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/net"
)

// Without the xray_doq tag a DNS over QUIC server must fail to be created, not be skipped.
func TestQUICNeedsTheDoqTag(t *testing.T) {
	dest := net.Destination{Network: net.Network_UDP, Address: net.DomainAddress("quic+local://1.1.1.1"), Port: 853}
	if _, err := NewServer(context.Background(), dest, nil, false, false, 0, nil); err == nil {
		t.Fatal("NewServer made a DNS over QUIC server; want an error")
	}
}
