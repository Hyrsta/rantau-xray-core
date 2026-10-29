package tun

import (
	"io"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

// sub-handler specifically for udp connections under main handler
type udpConnectionHandler struct {
	sync.Mutex

	udpConns map[net.Destination]*udpConn

	handleConnection func(conn net.Conn, dest net.Destination)
	writePacket      func(data []byte, src net.Destination, dst net.Destination) error
}

func newUdpConnectionHandler(handleConnection func(conn net.Conn, dest net.Destination), writePacket func(data []byte, src net.Destination, dst net.Destination) error) *udpConnectionHandler {
	handler := &udpConnectionHandler{
		udpConns:         make(map[net.Destination]*udpConn),
		handleConnection: handleConnection,
		writePacket:      writePacket,
	}

	return handler
}

// HandlePacket handles UDP packets coming from tun, to forward to the dispatcher
// this custom handler support FullCone NAT of returning packets, binding connection only by the source addr:port
func (u *udpConnectionHandler) HandlePacket(src net.Destination, dst net.Destination, data []byte, reject func() error) bool {
	u.Lock()
	conn, found := u.udpConns[src]
	if !found {
		egress := make(chan []byte, 16)
		conn = &udpConn{handler: u, egress: egress, src: src, dst: dst, reject: reject}
		if dst.Port == 443 && dst.Address.Family().IsIPv4() {
			udp443Attempts.Add(1)
		}
		u.udpConns[src] = conn

		go u.handleConnection(conn, dst)
	}

	// Keep channel send and close under the same lock; early rejection can race
	// the very first datagram.
	// send packet data to the egress channel, if it has buffer, or discard
	select {
	case conn.egress <- data:
	default:
	}

	u.Unlock()
	return true
}

func (u *udpConnectionHandler) connectionFinished(c *udpConn) {
	src := c.src
	u.Lock()
	conn, found := u.udpConns[src]
	if found && conn == c {
		delete(u.udpConns, src)
		close(conn.egress)
	}
	u.Unlock()
}

// udp connection abstraction
type udpConn struct {
	net.Conn
	buf.Writer

	handler *udpConnectionHandler

	egress     chan []byte
	src        net.Destination
	dst        net.Destination
	reject     func() error
	rejectOnce sync.Once
}

// Read packets from the connection
func (c *udpConn) Read(p []byte) (int, error) {
	data, ok := <-c.egress
	if !ok {
		return 0, io.EOF
	}

	n := copy(p, data)
	return n, nil
}

// Write returning packets back
func (c *udpConn) Write(p []byte) (int, error) {
	// sending packets back mean sending payload with source/destination reversed
	err := c.handler.writePacket(p, c.dst, c.src)
	if err != nil {
		return 0, nil
	}

	return len(p), nil
}

func (c *udpConn) Close() error {
	c.handler.connectionFinished(c)

	return nil
}

func (c *udpConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: c.dst.Address.IP(), Port: int(c.dst.Port.Value())}
}

func (c *udpConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: c.src.Address.IP(), Port: int(c.src.Port.Value())}
}

// Write returning packets back
func (c *udpConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for _, b := range mb {
		dst := c.dst
		if b.UDP != nil {
			dst = *b.UDP
		}

		// validate address family matches between buffer packet and the connection
		if dst.Address.Family() != c.dst.Address.Family() {
			continue
		}

		// sending packets back mean sending payload with source/destination reversed
		err := c.handler.writePacket(b.Bytes(), dst, c.src)
		if err != nil {
			// udp doesn't guarantee delivery, so in any failure we just continue to the next packet
			continue
		}
	}

	return nil
}

var udp443Attempts, rejectedUDP443 atomic.Int64

// UDP443Attempts counts new IPv4 UDP/443 TUN associations for this process.
// Full-cone associations are keyed by source address/port, not individual packets.
func UDP443Attempts() int64 { return udp443Attempts.Load() }

// RejectedUDP443 counts successfully emitted local IPv4 port-unreachable replies.
func RejectedUDP443() int64 { return rejectedUDP443.Load() }

func (c *udpConn) RejectUDP() {
	c.rejectOnce.Do(func() {
		if c.reject != nil && c.reject() == nil && c.dst.Port == 443 && c.dst.Address.Family().IsIPv4() {
			rejectedUDP443.Add(1)
		}
	})
}
