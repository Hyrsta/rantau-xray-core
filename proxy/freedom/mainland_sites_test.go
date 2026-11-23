package freedom

import (
	"context"
	"errors"
	gonet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
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
	for _, protocol := range []string{"tls", "http1", "http2", "quic"} {
		resolver := &fakeResolver{ips: []net.IP{net.ParseIP("43.175.44.34"), net.ParseIP("101.1.2.3"), net.ParseIP("101.1.2.4")}}
		target := net.TCPDestination(net.ParseAddress("43.175.44.34"), 443)
		want := net.TCPDestination(net.ParseAddress("101.1.2.3"), 443)
		if protocol == "quic" { // HTTP/3: a UDP flow
			target = net.UDPDestination(net.ParseAddress("43.175.44.34"), 443)
			want = net.UDPDestination(net.ParseAddress("101.1.2.3"), 443)
		}
		ctx, ob := sniffed(protocol, "y.qq.com", target)
		got := homeTarget(ctx, testHome, resolver, ob, target)
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
		{"UDP not QUIC", "bittorrent", "y.qq.com", net.UDPDestination(net.ParseAddress("43.175.44.34"), 443), &fakeResolver{ips: []net.IP{net.ParseIP("101.1.2.3")}}, testHome, false},
		{"UDP not sniffed", "", "y.qq.com", net.UDPDestination(net.ParseAddress("43.175.44.34"), 443), &fakeResolver{ips: []net.IP{net.ParseIP("101.1.2.3")}}, testHome, false},
		{"QUIC without a name", "quic", "", net.UDPDestination(net.ParseAddress("43.175.44.34"), 443), &fakeResolver{ips: []net.IP{net.ParseIP("101.1.2.3")}}, testHome, false},
		{"QUIC's name on TCP", "quic", "y.qq.com", abroad, &fakeResolver{ips: []net.IP{net.ParseIP("101.1.2.3")}}, testHome, false},
		{"TLS's name on UDP", "tls", "y.qq.com", net.UDPDestination(net.ParseAddress("43.175.44.34"), 443), &fakeResolver{ips: []net.IP{net.ParseIP("101.1.2.3")}}, testHome, false},
		{"QUIC to IPv6", "quic", "y.qq.com", net.UDPDestination(net.ParseAddress("2402:4e00::1"), 443), &fakeResolver{ips: []net.IP{net.ParseIP("101.1.2.3")}}, testHome, false},
		{"QUIC already home", "quic", "y.qq.com", net.UDPDestination(net.ParseAddress("101.9.9.9"), 443), &fakeResolver{ips: []net.IP{net.ParseIP("101.1.2.3")}}, testHome, false},
		{"QUIC, answer abroad too", "quic", "y.qq.com", net.UDPDestination(net.ParseAddress("43.175.44.34"), 443), &fakeResolver{ips: []net.IP{net.ParseIP("43.175.44.35")}}, testHome, true},
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

// recordingWriter keeps the datagrams' destinations.
type recordingWriter struct{ sent []net.Destination }

func (w *recordingWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for _, b := range mb {
		w.sent = append(w.sent, *b.UDP)
	}
	buf.ReleaseMulti(mb)
	return nil
}

func datagram(to net.Destination) *buf.Buffer {
	b := buf.New()
	b.WriteString("x")
	b.UDP = &to
	return b
}

// A re-pointed QUIC flow: its datagrams for the app's address go to the home address, any other
// destination is left as it is.
func TestHomePacketWriterMovesOnlyTheAppsAddress(t *testing.T) {
	app := net.UDPDestination(net.ParseAddress("43.175.44.34"), 443)
	home := net.UDPDestination(net.ParseAddress("101.1.2.3"), 443)
	otherPort := net.UDPDestination(net.ParseAddress("43.175.44.34"), 8443)
	other := net.UDPDestination(net.ParseAddress("43.175.44.35"), 443)
	rec := &recordingWriter{}
	w := &homePacketWriter{Writer: rec, from: app, to: home}
	if err := w.WriteMultiBuffer(buf.MultiBuffer{datagram(app), datagram(otherPort), datagram(other), datagram(app)}); err != nil {
		t.Fatal(err)
	}
	want := []net.Destination{home, otherPort, other, home}
	if len(rec.sent) != len(want) {
		t.Fatalf("sent %v, want %v", rec.sent, want)
	}
	for i := range want {
		if rec.sent[i] != want[i] {
			t.Errorf("datagram %d went to %v, want %v", i, rec.sent[i], want[i])
		}
	}
}

// The replies of the home address are given back as from the address the app sent to, so the app's
// QUIC connection keeps its peer. A real UDP socket stands in for the home server.
func TestRepointedFlowRepliesComeFromTheAppsAddress(t *testing.T) {
	server, err := gonet.ListenUDP("udp4", &gonet.UDPAddr{IP: gonet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := gonet.ListenUDP("udp4", &gonet.UDPAddr{IP: gonet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	homeAddr := server.LocalAddr().(*gonet.UDPAddr)
	conn := &net.PacketConnWrapper{PacketConn: client, Dest: homeAddr}
	app := net.UDPDestination(net.ParseAddress("43.175.44.34"), net.Port(homeAddr.Port))
	home := net.UDPDestination(net.IPAddress(homeAddr.IP), net.Port(homeAddr.Port))

	// Sent through the writer as the flow's app addressed it: it reaches the home server.
	writer := &homePacketWriter{Writer: NewPacketWriter(conn, &Handler{}, nil, net.UDPDestination(nil, 0), home, nil), from: app, to: home}
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{datagram(app)}); err != nil {
		t.Fatal(err)
	}
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, 16)
	_, from, err := server.ReadFromUDP(b)
	if err != nil {
		t.Fatalf("the home server got nothing: %v", err)
	}
	if _, err := server.WriteToUDP([]byte("reply"), from); err != nil {
		t.Fatal(err)
	}

	reader := NewPacketReader(conn, &Handler{}, nil, net.UDPDestination(nil, 0), app)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	mb, err := reader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(mb)
	if got := mb[0].UDP; got == nil || *got != app {
		t.Fatalf("reply given back as from %v, want %v", got, app)
	}
	if string(mb[0].Bytes()) != "reply" {
		t.Fatalf("reply %q", mb[0].Bytes())
	}
}
