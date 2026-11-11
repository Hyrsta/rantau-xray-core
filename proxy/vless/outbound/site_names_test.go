package outbound

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

func TestRequestTargetSendsSniffedTLSNameOnlyWhenAskedTo(t *testing.T) {
	ip := net.TCPDestination(net.ParseAddress("198.51.100.10"), 443)
	named := net.TCPDestination(net.DomainAddress("www.youtube.com"), 443)
	for _, c := range []struct {
		name      string
		siteNames bool
		protocol  string
		target    net.Destination
		route     net.Destination
		want      net.Destination
	}{
		{"tls", true, "tls", ip, named, named},
		{"tlsOtherPort", true, "tls", net.TCPDestination(net.ParseAddress("198.51.100.10"), 8443),
			net.TCPDestination(net.DomainAddress("www.youtube.com"), 8443), net.TCPDestination(net.DomainAddress("www.youtube.com"), 8443)},
		{"ipv6Target", true, "tls", net.TCPDestination(net.ParseAddress("2001:db8::10"), 443), named, named},
		{"off", false, "tls", ip, named, ip},
		{"http", true, "http", net.TCPDestination(net.ParseAddress("198.51.100.10"), 80),
			net.TCPDestination(net.DomainAddress("example.com"), 80), net.TCPDestination(net.ParseAddress("198.51.100.10"), 80)},
		{"notSniffed", true, "", ip, net.Destination{}, ip},
		{"sniffedIP", true, "tls", ip, net.TCPDestination(net.ParseAddress("203.0.113.7"), 443), ip},
		{"udp", true, "quic", net.UDPDestination(net.ParseAddress("198.51.100.10"), 443),
			net.UDPDestination(net.DomainAddress("www.youtube.com"), 443), net.UDPDestination(net.ParseAddress("198.51.100.10"), 443)},
		{"alreadyName", true, "tls", named, net.TCPDestination(net.DomainAddress("other.example"), 443), named},
		{"mux", true, "tls", ip, net.TCPDestination(net.DomainAddress("v1.mux.cool"), 443), ip},
		{"reverse", true, "tls", ip, net.TCPDestination(net.DomainAddress("v1.rvs.cool"), 443), ip},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx := session.ContextWithContent(context.Background(), &session.Content{Protocol: c.protocol})
			ob := &session.Outbound{Target: c.target, RouteTarget: c.route}
			if got := requestTarget(ctx, c.siteNames, ob); got != c.want {
				t.Fatalf("got %v, want %v", got, c.want)
			}
			if ob.Target != c.target {
				t.Fatalf("the routed target changed to %v", ob.Target)
			}
		})
	}
	ob := &session.Outbound{Target: ip, RouteTarget: named}
	if got := requestTarget(context.Background(), true, ob); got != ip {
		t.Fatalf("without content: got %v", got)
	}
}

func TestSiteNamesOnlyForInstancesThatAskForIt(t *testing.T) {
	if siteNamesEnabled(context.Background()) {
		t.Fatal("on without WithSiteNames")
	}
	if !siteNamesEnabled(WithSiteNames(context.Background())) {
		t.Fatal("off with WithSiteNames")
	}
}
