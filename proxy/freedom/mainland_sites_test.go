package freedom

import (
	"context"
	"errors"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/dns"
)

// fakeResolver answers every name with the same addresses (or error) and counts lookups.
type fakeResolver struct {
	ips     []net.IP
	err     error
	lookups int
	asked   string
	option  dns.IPOption
}

func (*fakeResolver) Type() interface{} { return dns.ClientType() }
func (*fakeResolver) Start() error      { return nil }
func (*fakeResolver) Close() error      { return nil }
func (r *fakeResolver) LookupIP(domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	r.lookups++
	r.asked, r.option = domain, option
	return r.ips, 60, r.err
}

// home in these tests: 101.0.0.0/8 stands for the mainland.
func testHome(ip net.IP) bool { return ip.To4() != nil && ip.To4()[0] == 101 }

func sniffed(protocol, name string, target net.Destination) (context.Context, *session.Outbound) {
	ctx := session.ContextWithContent(context.Background(), &session.Content{Protocol: protocol})
	ob := &session.Outbound{Target: target}
	if name != "" {
		ob.RouteTarget = net.Destination{Network: target.Network, Address: net.DomainAddress(name), Port: target.Port}
	}
	return ctx, ob
}

func TestHomeTargetMovesASiteAbroadHome(t *testing.T) {
	for _, protocol := range []string{"tls", "http1", "http2"} {
		resolver := &fakeResolver{ips: []net.IP{net.ParseIP("43.175.44.34"), net.ParseIP("101.1.2.3"), net.ParseIP("101.1.2.4")}}
		target := net.TCPDestination(net.ParseAddress("43.175.44.34"), 443)
		ctx, ob := sniffed(protocol, "y.qq.com", target)
		got := homeTarget(ctx, testHome, resolver, ob, target)
		want := net.TCPDestination(net.ParseAddress("101.1.2.3"), 443)
		if got != want {
			t.Errorf("%s: got %v, want %v", protocol, got, want)
		}
		if resolver.asked != "y.qq.com" || !resolver.option.IPv4Enable || resolver.option.IPv6Enable {
			t.Errorf("%s: asked %q with %+v, want y.qq.com, IPv4 only", protocol, resolver.asked, resolver.option)
		}
	}
}

func TestHomeTargetLeavesEverythingElse(t *testing.T) {
	abroad := net.TCPDestination(net.ParseAddress("43.175.44.34"), 443)
	cases := []struct {
		name     string
		protocol string
		site     string
		target   net.Destination
		resolver *fakeResolver
		home     func(net.IP) bool
		asks     bool
	}{
		{"already home", "tls", "y.qq.com", net.TCPDestination(net.ParseAddress("101.9.9.9"), 443), &fakeResolver{ips: []net.IP{net.ParseIP("101.1.2.3")}}, testHome, false},
		{"UDP (QUIC)", "quic", "y.qq.com", net.UDPDestination(net.ParseAddress("43.175.44.34"), 443), &fakeResolver{ips: []net.IP{net.ParseIP("101.1.2.3")}}, testHome, false},
		{"no sniffed name", "tls", "", abroad, &fakeResolver{ips: []net.IP{net.ParseIP("101.1.2.3")}}, testHome, false},
		{"not sniffed", "", "y.qq.com", abroad, &fakeResolver{ips: []net.IP{net.ParseIP("101.1.2.3")}}, testHome, false},
		{"other protocol", "bittorrent", "y.qq.com", abroad, &fakeResolver{ips: []net.IP{net.ParseIP("101.1.2.3")}}, testHome, false},
		{"private network", "tls", "intranet.example.cn", net.TCPDestination(net.ParseAddress("10.1.2.3"), 443), &fakeResolver{ips: []net.IP{net.ParseIP("101.1.2.3")}}, testHome, false},
		{"shared address space", "tls", "portal.example.cn", net.TCPDestination(net.ParseAddress("100.70.1.1"), 443), &fakeResolver{ips: []net.IP{net.ParseIP("101.1.2.3")}}, testHome, false},
		{"link local", "http1", "router.example.cn", net.TCPDestination(net.ParseAddress("169.254.1.1"), 80), &fakeResolver{ips: []net.IP{net.ParseIP("101.1.2.3")}}, testHome, false},
		{"loopback", "tls", "y.qq.com", net.TCPDestination(net.ParseAddress("127.0.0.1"), 443), &fakeResolver{ips: []net.IP{net.ParseIP("101.1.2.3")}}, testHome, false},
		{"IPv6", "tls", "y.qq.com", net.TCPDestination(net.ParseAddress("2402:4e00::1"), 443), &fakeResolver{ips: []net.IP{net.ParseIP("101.1.2.3")}}, testHome, false},
		{"domain target", "tls", "y.qq.com", net.TCPDestination(net.DomainAddress("y.qq.com"), 443), &fakeResolver{ips: []net.IP{net.ParseIP("101.1.2.3")}}, testHome, false},
		{"not opted in", "tls", "y.qq.com", abroad, &fakeResolver{ips: []net.IP{net.ParseIP("101.1.2.3")}}, nil, false},
		{"answer abroad too", "tls", "y.qq.com", abroad, &fakeResolver{ips: []net.IP{net.ParseIP("43.175.44.35")}}, testHome, true},
		{"answer local", "tls", "y.qq.com", abroad, &fakeResolver{ips: []net.IP{net.ParseIP("192.168.1.1")}}, func(ip net.IP) bool { return testHome(ip) || ip.IsPrivate() }, true},
		{"empty answer", "tls", "y.qq.com", abroad, &fakeResolver{}, testHome, true},
		{"lookup failed", "tls", "y.qq.com", abroad, &fakeResolver{ips: []net.IP{net.ParseIP("101.1.2.3")}, err: errors.New("timeout")}, testHome, true},
	}
	for _, c := range cases {
		ctx, ob := sniffed(c.protocol, c.site, c.target)
		if c.protocol == "" {
			ctx = context.Background()
		}
		if got := homeTarget(ctx, c.home, c.resolver, ob, c.target); got != c.target {
			t.Errorf("%s: got %v, want %v unchanged", c.name, got, c.target)
		}
		if asked := c.resolver.lookups > 0; asked != c.asks {
			t.Errorf("%s: looked up %d times, want lookup %v", c.name, c.resolver.lookups, c.asks)
		}
	}
}

func TestMainlandSitesOptIn(t *testing.T) {
	if mainlandSitesFrom(context.Background()) != nil {
		t.Fatal("an instance that did not opt in moves connections")
	}
	if mainlandSitesFrom(WithMainlandSites(context.Background(), testHome)) == nil {
		t.Fatal("the opt-in was lost")
	}
}
