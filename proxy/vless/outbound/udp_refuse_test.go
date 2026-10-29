package outbound

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Stop at the dial boundary without network access or waiting through retries.
type dialBoundary struct{}

func (dialBoundary) Dial(context.Context, net.Destination) (stat.Connection, error) {
	panic(dialBoundary{})
}
func (dialBoundary) DestIpAddress() net.IP                                 { return nil }
func (dialBoundary) SetOutboundGateway(context.Context, *session.Outbound) {}

func TestUDPRefusalOnlyForUnsupportedVisionUDP443(t *testing.T) {
	for _, c := range []struct {
		name, flow string
		target     net.Destination
		reject     bool
	}{
		{"vision443", vless.XRV, net.UDPDestination(net.ParseAddress("198.51.100.10"), 443), true},
		{"visionDomain443", vless.XRV, net.UDPDestination(net.DomainAddress("instagram.com"), 443), true},
		{"enabled443", vless.XRV + "-udp443", net.UDPDestination(net.ParseAddress("198.51.100.10"), 443), false},
		{"plain443", "", net.UDPDestination(net.ParseAddress("198.51.100.10"), 443), false},
		{"dns", vless.XRV, net.UDPDestination(net.ParseAddress("198.51.100.10"), 53), false},
		{"tcp", vless.XRV, net.TCPDestination(net.ParseAddress("198.51.100.10"), 443), false},
		{"mux", vless.XRV, net.UDPDestination(net.DomainAddress("v1.mux.cool"), 443), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := &Handler{server: &protocol.ServerSpec{User: &protocol.MemoryUser{Account: &vless.MemoryAccount{Flow: c.flow}}}}
			ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: c.target}})
			refused := false
			ctx = session.ContextWithUDPReject(ctx, func() { refused = true })
			dialed := false
			func() {
				defer func() {
					if p := recover(); p != nil {
						if _, ok := p.(dialBoundary); !ok {
							panic(p)
						}
						dialed = true
					}
				}()
				h.Process(ctx, &transport.Link{}, dialBoundary{})
			}()
			if refused != c.reject || dialed == c.reject {
				t.Fatalf("refused=%v dialed=%v, want refusal=%v", refused, dialed, c.reject)
			}
		})
	}
}
