package outbound

import (
	"context"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

type siteNamesKey struct{}

// WithSiteNames makes the VLESS outbounds of an instance built with this context ask their server
// for the site a TLS connection names (its SNI, read by routeOnly sniffing) instead of the address
// the app connected to. The server then looks the name up itself, so a server with IPv6 exits can
// reach the site over IPv6, with IPv4 as its fallback, although the app connected over IPv4.
// Only TCP connections whose sniffed protocol is TLS change; everything else is sent as before.
// Other users of this Xray copy keep normal behavior unless they opt in.
func WithSiteNames(ctx context.Context) context.Context {
	return context.WithValue(ctx, siteNamesKey{}, true)
}

func siteNamesEnabled(ctx context.Context) bool {
	enabled, _ := ctx.Value(siteNamesKey{}).(bool)
	return enabled
}

// requestTarget is the destination asked of the server: the sniffed TLS name in place of an IP
// address when site names are on, otherwise the target itself.
func requestTarget(ctx context.Context, siteNames bool, ob *session.Outbound) net.Destination {
	target := ob.Target
	if !siteNames || target.Network != net.Network_TCP || target.Address == nil || !target.Address.Family().IsIP() {
		return target
	}
	name := ob.RouteTarget.Address
	if name == nil || !name.Family().IsDomain() || len(name.Domain()) > 253 {
		return target
	}
	// Names the protocol itself uses (mux, reverse) would change the request's meaning.
	if candidate := (net.Destination{Address: name}); isMuxTarget(candidate) {
		return target
	}
	if content := session.ContentFromContext(ctx); content == nil || content.Protocol != "tls" {
		return target
	}
	return net.Destination{Network: net.Network_TCP, Address: name, Port: target.Port}
}
