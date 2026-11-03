package tun

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
)

type connectionFunc func(net.Conn, net.Destination)

func (f connectionFunc) HandleConnection(conn net.Conn, dest net.Destination) { f(conn, dest) }

// newRefusingStack is a stack as Handler builds it, with RefuseIPv6 as asked
func newRefusingStack(t *testing.T, l *link, refuseIPv6 bool, handle func(net.Conn, net.Destination)) {
	t.Helper()
	s, err := NewStack(context.Background(), StackOptions{Tun: l, MTU: testMTU, RefuseIPv6: refuseIPv6}, connectionFunc(handle))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.Close()
		l.Close()
	})
}

// refusal reads the ICMP message of a packet that the stack wrote, from from to to, with its checksums looked at
func refusal(t *testing.T, b []byte, from, to netip.Addr) []byte {
	t.Helper()
	packet, ok := parsePacket(b, 0)
	proto := byte(protoICMPv4)
	if from.Is6() {
		proto = protoICMPv6
	}
	if !ok || packet.proto != proto || packet.src != from || packet.dst != to || len(packet.payload) < 8 {
		t.Fatal("not a refusal from ", from, " to ", to, ": ", b)
	}
	m := packet.payload
	if from.Is4() {
		if checksum(sum(b[:ipv4HeaderSize], 0)) != 0 || checksum(sum(m, 0)) != 0 {
			t.Fatal("wrong checksum of the refusal")
		}
	} else if transportChecksum(b[:ipv6HeaderSize], protoICMPv6, m, nil) != 0 {
		t.Fatal("wrong checksum of the refusal")
	}
	return m
}

// IPv6 is refused at once when the instance asks for it, so that programs use IPv4 instead; IPv4 is taken
func TestIPv6RefusedAtOnceAndIPv4Taken(t *testing.T) {
	conns := make(chan accepted, 4)
	p, l := newPeer(t, "[fd49:6e64:6f6e::2]:40001", "[2001:db8::1]:443")
	newRefusingStack(t, l, true, accept(conns))
	p.send(p.seq, tcpSyn, nil, nil)
	if s := p.receive(); s.flags&tcpRst == 0 || s.ack != p.seq+1 {
		t.Fatal("IPv6 SYN answered with flags ", s.flags, ", ack ", s.ack, ", not a reset")
	}
	datagram := udpPacket(netip.MustParseAddrPort("[fd49:6e64:6f6e::2]:40002"), p.dst, []byte("QUIC to IPv6"))
	l.in <- datagram
	m := refusal(t, p.packet(), p.dst.Addr(), p.src.Addr())
	if m[0] != 1 || m[1] != 4 || !bytes.Equal(m[8:], datagram[:ipv6HeaderSize+udpHeaderSize]) {
		t.Fatal("IPv6 UDP answered with ", m[:2], " quoting ", m[8:])
	}
	select {
	case a := <-conns:
		t.Fatal("refused IPv6 handed over to ", a.dest)
	case <-time.After(50 * time.Millisecond):
	}

	p4, l4 := newPeer(t, "172.19.0.2:40003", "198.51.100.10:443")
	newRefusingStack(t, l4, true, accept(conns))
	p4.connect(nil)
	if a := take(t, conns); a.dest.NetAddr() != "198.51.100.10:443" {
		t.Fatal("IPv4 handed over to ", a.dest)
	}
}

// Without RefuseIPv6 nothing changes for IPv6: other users of the TUN inbound keep it
func TestIPv6TakenWithoutRefusal(t *testing.T) {
	conns := make(chan accepted, 1)
	p, l := newPeer(t, "[fd49:6e64:6f6e::2]:40004", "[2001:db8::1]:443")
	newRefusingStack(t, l, false, accept(conns))
	p.connect(nil)
	take(t, conns)
}

// An outbound that refuses UDP/443 (VLESS with Vision) makes the stack answer port unreachable, quoting only
// the IP and UDP headers of the datagram. Other ports and IPv6 are not answered that way
func TestRefusedUDP443QuotesOnlyHeaders(t *testing.T) {
	p, l := newPeer(t, "172.19.0.2:43001", "198.51.100.10:443")
	newRefusingStack(t, l, false, func(conn net.Conn, _ net.Destination) {
		conn.(interface{ RejectUDP() }).RejectUDP()
		conn.Close()
	})
	rejected := RejectedUDP443()
	datagram := udpPacket(p.src, p.dst, []byte("secret QUIC payload"))
	// a checksum of zero is none, which IPv4 allows
	l.in <- datagram
	m := refusal(t, p.packet(), p.dst.Addr(), p.src.Addr())
	if m[0] != 3 || m[1] != 3 || !bytes.Equal(m[8:], datagram[:ipv4HeaderSize+udpHeaderSize]) || bytes.Contains(m, []byte("secret")) {
		t.Fatal("UDP/443 answered with ", m[:2], " quoting ", m[8:])
	}
	for deadline := time.Now().Add(time.Second); RejectedUDP443() != rejected+1; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("refusal not counted")
		}
	}

	l.in <- udpPacket(p.src, netip.MustParseAddrPort("198.51.100.10:3478"), []byte("STUN"))
	l.in <- udpPacket(netip.MustParseAddrPort("[fd49:6e64:6f6e::2]:43002"), netip.MustParseAddrPort("[2001:db8::1]:443"), []byte("QUIC"))
	p.silent(100 * time.Millisecond)
	if RejectedUDP443() != rejected+1 {
		t.Fatal("other datagrams counted as refused")
	}
}

// What came in fragments has no header of its own to quote, and is not answered
func TestFragmentedUDP443NotQuoted(t *testing.T) {
	p, l := newPeer(t, "172.19.0.2:43003", "198.51.100.10:443")
	handed := make(chan struct{}, 1)
	newRefusingStack(t, l, false, func(conn net.Conn, _ net.Destination) {
		conn.(interface{ RejectUDP() }).RejectUDP()
		conn.Close()
		handed <- struct{}{}
	})
	datagram := udpPacket(p.src, p.dst, bytes.Repeat([]byte{7}, 64))
	first, second := bytes.Clone(datagram[:ipv4HeaderSize+40]), append(bytes.Clone(datagram[:ipv4HeaderSize]), datagram[ipv4HeaderSize+40:]...)
	binary.BigEndian.PutUint16(first[4:], 77)
	binary.BigEndian.PutUint16(first[6:], 0x2000)
	setIPLength(first[:ipv4HeaderSize], len(first))
	binary.BigEndian.PutUint16(second[4:], 77)
	binary.BigEndian.PutUint16(second[6:], 40/8)
	setIPLength(second[:ipv4HeaderSize], len(second))
	l.in <- first
	l.in <- second
	select {
	case <-handed:
	case <-time.After(time.Second):
		t.Fatal("reassembled datagram not handed over")
	}
	p.silent(100 * time.Millisecond)
}
