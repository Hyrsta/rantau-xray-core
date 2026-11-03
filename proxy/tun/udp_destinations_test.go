package tun

import (
	"bytes"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

type udpDispatch struct {
	conn *udpConn
	dest net.Destination
}

func udpTestHandler(t *testing.T, reply func([]byte, net.Destination, net.Destination) error) (*udpConnectionHandler, chan udpDispatch) {
	t.Helper()
	dispatched := make(chan udpDispatch, 16)
	h := newUdpConnectionHandler(func(c net.Conn, dest net.Destination) { dispatched <- udpDispatch{c.(*udpConn), dest} }, reply)
	t.Cleanup(func() {
		h.Lock()
		conns := make([]*udpConn, 0, len(h.udpConns))
		for _, c := range h.udpConns {
			conns = append(conns, c)
		}
		h.Unlock()
		for _, c := range conns {
			c.Close()
		}
	})
	return h, dispatched
}

func udpPayload(p string) *buf.Buffer {
	b := buf.New()
	b.WriteString(p)
	return b
}

func nextUDPDispatch(t *testing.T, dispatched <-chan udpDispatch, want net.Destination) *udpConn {
	t.Helper()
	select {
	case got := <-dispatched:
		if got.dest != want {
			t.Fatalf("routed to %v, want %v", got.dest, want)
		}
		return got.conn
	case <-time.After(time.Second):
		t.Fatalf("destination %v received no routing decision", want)
		return nil
	}
}

func requireUDPRead(t *testing.T, c *udpConn, want string) {
	t.Helper()
	data := make([]byte, 256)
	n, err := c.Read(data)
	if err != nil || !bytes.Equal(data[:n], []byte(want)) {
		t.Fatalf("payload %q (%v), want %q", data[:n], err, want)
	}
}

// ICE/STUN clients commonly send to multiple destinations from one UDP socket.
// Each must be routed independently; neither a different address nor a port may
// inherit the first packet's destination or its direct/proxy route.
func TestUDPSameSocketRoutesEachDestination(t *testing.T) {
	src := net.UDPDestination(net.ParseAddress("172.19.0.2"), 41000)
	destinations := []net.Destination{
		net.UDPDestination(net.ParseAddress("198.51.100.1"), 3478),
		net.UDPDestination(net.ParseAddress("198.51.100.2"), 3478),
		net.UDPDestination(net.ParseAddress("198.51.100.1"), 443),
		net.UDPDestination(net.ParseAddress("192.168.1.1"), 443),
	}
	h, dispatched := udpTestHandler(t, nil)
	conns := make([]*udpConn, 0, len(destinations))
	for i, dst := range destinations {
		payload := string(rune('a' + i))
		h.HandlePacket(src, dst, udpPayload(payload))
		c := nextUDPDispatch(t, dispatched, dst)
		requireUDPRead(t, c, payload)
		conns = append(conns, c)
	}
	// Fresh address objects from packet parsing must reuse the same association.
	for i, dst := range destinations {
		parsedSrc := net.UDPDestination(net.IPAddress([]byte{172, 19, 0, 2}), 41000)
		parsedDst := net.UDPDestination(net.IPAddress(dst.Address.IP()), dst.Port)
		h.HandlePacket(parsedSrc, parsedDst, udpPayload("repeat"))
		requireUDPRead(t, conns[i], "repeat")
	}
	select {
	case got := <-dispatched:
		t.Fatalf("same tuple created another association: %v", got.dest)
	default:
	}
}

// A refused foreign QUIC destination cannot close a domestic UDP association or
// invoke that association's ICMP callback merely because the app reuses a socket.
func TestUDPRefusalIsIsolatedToDestination(t *testing.T) {
	src := net.UDPDestination(net.ParseAddress("172.19.0.2"), 41001)
	direct := net.UDPDestination(net.ParseAddress("192.168.1.1"), 443)
	proxy := net.UDPDestination(net.ParseAddress("198.51.100.1"), 443)
	h, dispatched := udpTestHandler(t, nil)
	var mu sync.Mutex
	refusals := map[net.Destination][]string{}
	h.refusePacket = func(quote []byte, from, to net.Destination) error {
		mu.Lock()
		defer mu.Unlock()
		if from != src {
			t.Errorf("refusal for %v", from)
		}
		refusals[to] = append(refusals[to], string(quote))
		return nil
	}
	attempts, rejected := UDP443Attempts(), RejectedUDP443()
	directQuote := []byte("direct headers")
	h.HandleRefusablePacket(src, direct, udpPayload("direct"), directQuote)
	// the handler keeps its own copy of the headers, the stack reuses its buffer
	copy(directQuote, "XXXXXXXXXXXXXX")
	dc := nextUDPDispatch(t, dispatched, direct)
	requireUDPRead(t, dc, "direct")
	h.HandleRefusablePacket(src, proxy, udpPayload("proxy"), []byte("proxy headers"))
	pc := nextUDPDispatch(t, dispatched, proxy)
	requireUDPRead(t, pc, "proxy")
	pc.RejectUDP()
	pc.RejectUDP()
	pc.Close()
	h.HandlePacket(src, direct, udpPayload("still direct"))
	requireUDPRead(t, dc, "still direct")
	mu.Lock()
	if len(refusals[direct]) != 0 || len(refusals[proxy]) != 1 || refusals[proxy][0] != "proxy headers" {
		t.Fatalf("refusals %v", refusals)
	}
	mu.Unlock()
	if UDP443Attempts() != attempts+2 || RejectedUDP443() != rejected+1 {
		t.Fatalf("counters: attempts +%d, rejected +%d", UDP443Attempts()-attempts, RejectedUDP443()-rejected)
	}
	dc.RejectUDP()
	mu.Lock()
	defer mu.Unlock()
	if len(refusals[direct]) != 1 || refusals[direct][0] != "direct headers" {
		t.Fatalf("direct refusal quoted %v", refusals[direct])
	}
}

func TestUDPDestinationRepliesKeepTheirSourceAndFullConeMetadata(t *testing.T) {
	src := net.UDPDestination(net.ParseAddress("172.19.0.2"), 41002)
	first := net.UDPDestination(net.ParseAddress("198.51.100.1"), 3478)
	second := net.UDPDestination(net.ParseAddress("198.51.100.2"), 3478)
	alternate := net.UDPDestination(net.ParseAddress("198.51.100.3"), 50000)
	type reply struct {
		from, to net.Destination
		payload  string
	}
	replies := make(chan reply, 3)
	h, dispatched := udpTestHandler(t, func(p []byte, from, to net.Destination) error { replies <- reply{from, to, string(p)}; return nil })
	h.HandlePacket(src, first, udpPayload("a"))
	fc := nextUDPDispatch(t, dispatched, first)
	h.HandlePacket(src, second, udpPayload("b"))
	sc := nextUDPDispatch(t, dispatched, second)
	fc.Write([]byte("first"))
	sc.Write([]byte("second"))
	b := buf.New()
	b.Write([]byte("alternate"))
	b.UDP = &alternate
	if err := fc.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []reply{{first, src, "first"}, {second, src, "second"}, {alternate, src, "alternate"}} {
		if got := <-replies; got != want {
			t.Fatalf("reply %+v, want %+v", got, want)
		}
	}
}

func TestUDPConcurrentDestinationsKeepPayloadsSeparate(t *testing.T) {
	src := net.UDPDestination(net.ParseAddress("172.19.0.2"), 41003)
	var workers sync.WaitGroup
	h := newUdpConnectionHandler(func(c net.Conn, dest net.Destination) {
		defer workers.Done()
		defer c.Close()
		p := make([]byte, 64)
		for {
			n, err := c.Read(p)
			if err != nil {
				return
			}
			if n != 1 || p[0] != byte(dest.Port-5000) {
				t.Errorf("payload %v sent to %v", p[:n], dest)
			}
		}
	}, nil)
	destinations := make([]net.Destination, 4)
	for i := range destinations {
		destinations[i] = net.UDPDestination(net.ParseAddress("198.51.100.1"), net.Port(5000+i))
		workers.Add(1)
		h.HandlePacket(src, destinations[i], udpPayload(string([]byte{byte(i)})))
	}
	var senders sync.WaitGroup
	for i, dst := range destinations {
		senders.Add(1)
		go func(i int, dst net.Destination) {
			defer senders.Done()
			for j := 0; j < 100; j++ {
				h.HandlePacket(src, dst, udpPayload(string([]byte{byte(i)})))
			}
		}(i, dst)
	}
	senders.Wait()
	h.Lock()
	conns := make([]*udpConn, 0, len(h.udpConns))
	for _, c := range h.udpConns {
		conns = append(conns, c)
	}
	h.Unlock()
	for _, c := range conns {
		c.Close()
	}
	workers.Wait()
}

func TestUDPDirectTrafficStillReturnsData(t *testing.T) {
	src := net.UDPDestination(net.ParseAddress("172.19.0.2"), 40000)
	dst := net.UDPDestination(net.ParseAddress("192.168.1.1"), 443)
	replied := make(chan []byte, 1)
	var refused sync.Once
	refusedAny := false
	h := newUdpConnectionHandler(func(c net.Conn, _ net.Destination) {
		defer c.Close()
		b := make([]byte, 64)
		n, err := c.Read(b)
		if err == nil {
			c.Write(b[:n])
		}
	}, func(b []byte, from, to net.Destination) error {
		if from != dst || to != src {
			t.Error("return direction changed")
		}
		replied <- append([]byte(nil), b...)
		return nil
	})
	h.refusePacket = func([]byte, net.Destination, net.Destination) error {
		refused.Do(func() { refusedAny = true })
		return nil
	}
	h.HandleRefusablePacket(src, dst, udpPayload("direct QUIC"), []byte("headers"))
	select {
	case b := <-replied:
		if !bytes.Equal(b, []byte("direct QUIC")) {
			t.Fatal("payload changed")
		}
	case <-time.After(time.Second):
		t.Fatal("no UDP reply")
	}
	if refusedAny {
		t.Fatal("direct traffic refused")
	}
}

func TestUDPEarlyRefusalDoesNotRacePacketSendOrReplacement(t *testing.T) {
	src := net.UDPDestination(net.ParseAddress("172.19.0.2"), 40001)
	dst := net.UDPDestination(net.ParseAddress("198.51.100.1"), 443)
	var done sync.WaitGroup
	h := newUdpConnectionHandler(func(c net.Conn, _ net.Destination) {
		c.(*udpConn).RejectUDP()
		c.Close()
		_, err := c.Read(make([]byte, 32))
		if err != nil && err != io.EOF {
			t.Error(err)
		}
		done.Done()
	}, nil)
	h.refusePacket = func([]byte, net.Destination, net.Destination) error { return nil }
	// Each creation adds once under the same handler lock as creation; the refusal
	// can immediately close while the producer is enqueueing the first datagram.
	for i := 0; i < 100; i++ {
		done.Add(1)
		h.HandleRefusablePacket(src, dst, udpPayload("x"), []byte("headers"))
		done.Wait()
	}
	old := &udpConn{handler: h, src: src, dst: dst, queue: newPacketQueue(1)}
	current := &udpConn{handler: h, src: src, dst: dst, queue: newPacketQueue(1)}
	flow := udpFlow{src: src, dst: dst}
	h.udpConns[flow] = current
	old.Close()
	if h.udpConns[flow] != current {
		t.Fatal("stale close deleted replacement")
	}
	current.Close()
}
