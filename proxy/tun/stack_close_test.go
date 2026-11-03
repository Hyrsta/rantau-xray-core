package tun

import (
	"net/netip"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

// A closed stack ends its UDP flows at once. A flow left waiting for a packet kept its connection, and through
// its context the dispatcher and the whole closed instance, until the idle timeout: an app that restarts the
// instance (Android reconnects) collected one instance per restart.
func TestCloseEndsUDPFlows(t *testing.T) {
	p, l := newPeer(t, "10.0.0.2:40000", "1.2.3.4:53")
	opened := make(chan net.Destination, 4)
	ended := make(chan net.Destination, 4)
	s := newTestStack(t, l, func(conn net.Conn, dest net.Destination) {
		defer conn.Close()
		opened <- dest
		for {
			mb, err := conn.(buf.Reader).ReadMultiBuffer()
			if err != nil {
				ended <- dest
				return
			}
			buf.ReleaseMulti(mb)
		}
	})
	other := netip.MustParseAddrPort("5.6.7.8:443")
	p.udp(p.src, p.dst, "query")
	p.udp(p.src, other, "other")
	for range 2 {
		select {
		case <-opened:
		case <-time.After(5 * time.Second):
			t.Fatal("a flow did not open")
		}
	}

	s.Close()
	for range 2 {
		select {
		case <-ended:
		case <-time.After(time.Second):
			t.Fatal("a flow outlived the closed stack")
		}
	}
	s.udp.RLock()
	left := len(s.udp.udpConns)
	s.udp.RUnlock()
	if left != 0 {
		t.Fatal("flows left in the closed stack: ", left)
	}

	// a packet still on its way opens nothing
	p.udp(p.src, netip.MustParseAddrPort("9.9.9.9:53"), "late")
	select {
	case dest := <-opened:
		t.Fatal("a flow opened after the stack closed: ", dest)
	case <-time.After(200 * time.Millisecond):
	}
}
