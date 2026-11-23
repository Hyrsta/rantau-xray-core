package freedom

import (
	"context"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/dns"
)

type mainlandSitesKey struct{}

// WithMainlandSites makes the freedom outbounds of an instance built with this context connect a site
// to its address at home when the app picked one abroad. The case: a TCP connection whose sniffed name
// (TLS or HTTP, read by routeOnly sniffing) was routed to freedom, to a public IPv4 address for which
// home is false. The instance's own resolver is asked for the name, and the first IPv4 address of its
// answer for which home is true replaces the app's address. The app gets the same site from a server
// nearby: a browser that looks names up over its own DNS over HTTPS through a proxy, for example, is
// given a Chinese site's overseas servers, and a direct connection to those from inside China crosses
// the border (the page took 4 to 8 s instead of 0.2 s, 2026-11-23).
//
// Everything else is dialed as before: UDP, IPv6, local and reserved addresses, addresses for which home
// is true, connections without a sniffed name, and names whose answer has no home address or fails.
// Other users of this Xray copy keep normal behavior unless they opt in.
func WithMainlandSites(ctx context.Context, home func(net.IP) bool) context.Context {
	return context.WithValue(ctx, mainlandSitesKey{}, home)
}

func mainlandSitesFrom(ctx context.Context) func(net.IP) bool {
	home, _ := ctx.Value(mainlandSitesKey{}).(func(net.IP) bool)
	return home
}

// cgnat is 100.64.0.0/10, shared address space: a carrier's or a campus's own network, like the
// private ranges.
var cgnat = net.IPNet{IP: net.IP{100, 64, 0, 0}, Mask: net.CIDRMask(10, 32)}

// public reports an IPv4 address on the internet, not a local, reserved or multicast one.
func public(ip net.IP) bool {
	return !(ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() ||
		ip.IsUnspecified() || cgnat.Contains(ip) || ip[0] == 0 || ip[0] >= 240)
}

// nameProtocols are the TCP sniffers whose name says which site the connection is for.
var nameProtocols = map[string]bool{"tls": true, "http1": true, "http2": true}

// homeTarget is the destination to dial: the target, or the same port at the name's home address (see
// WithMainlandSites).
func homeTarget(ctx context.Context, home func(net.IP) bool, resolver dns.Client, ob *session.Outbound, target net.Destination) net.Destination {
	if home == nil || resolver == nil || target.Network != net.Network_TCP || target.Address == nil || !target.Address.Family().IsIPv4() {
		return target
	}
	if ip := target.Address.IP().To4(); ip == nil || !public(ip) || home(ip) {
		return target
	}
	name := ob.RouteTarget.Address
	if name == nil || !name.Family().IsDomain() {
		return target
	}
	if content := session.ContentFromContext(ctx); content == nil || !nameProtocols[content.Protocol] {
		return target
	}
	ips, _, err := resolver.LookupIP(name.Domain(), dns.IPOption{IPv4Enable: true})
	if err != nil {
		return target
	}
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil && public(ip4) && home(ip4) {
			errors.LogInfo(ctx, "connecting ", name.Domain(), " at home ", ip4, " instead of ", target.Address)
			return net.Destination{Network: net.Network_TCP, Address: net.IPAddress(ip4), Port: target.Port}
		}
	}
	return target
}
