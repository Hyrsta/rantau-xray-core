package tun

import (
	"bytes"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
)

func TestUDPDirectTrafficStillReturnsData(t *testing.T) {
	src := net.UDPDestination(net.ParseAddress("172.19.0.2"), 40000)
	dst := net.UDPDestination(net.ParseAddress("192.168.1.1"), 443)
	replied := make(chan []byte, 1)
	refused := false
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
	h.HandlePacket(src, dst, []byte("direct QUIC"), func() error { refused = true; return nil })
	select {
	case b := <-replied:
		if !bytes.Equal(b, []byte("direct QUIC")) {
			t.Fatal("payload changed")
		}
	case <-time.After(time.Second):
		t.Fatal("no UDP reply")
	}
	if refused {
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
	// Each creation adds once under the same handler lock as creation; reject callback
	// can immediately close while the producer is enqueueing the first datagram.
	for i := 0; i < 100; i++ {
		done.Add(1)
		h.HandlePacket(src, dst, []byte("x"), func() error { return nil })
		done.Wait()
	}
	old := &udpConn{handler: h, src: src, dst: dst, egress: make(chan []byte, 1)}
	current := &udpConn{handler: h, src: src, dst: dst, egress: make(chan []byte, 1)}
	flow := udpFlow{src: src, dst: dst}
	h.udpConns[flow] = current
	old.Close()
	if h.udpConns[flow] != current {
		t.Fatal("stale close deleted replacement")
	}
	current.Close()
}
