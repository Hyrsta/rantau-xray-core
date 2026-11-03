package tun

import (
	"bytes"
	"context"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

// A source socket can send to several destinations. The dispatcher chooses one
// route per connection, so each source/destination pair needs its own connection.
// Xray IP addresses are comparable value types, including freshly parsed IPs.
type udpFlow struct {
	src, dst net.Destination
}

// sub-handler specifically for udp connections under main handler
type udpConnectionHandler struct {
	sync.RWMutex

	udpConns map[udpFlow]*udpConn
	// closed is set by closeAll: the stack has closed, and a packet still on its way opens no flow
	closed bool

	handleConnection func(conn net.Conn, dest net.Destination)
	writePacket      func(data []byte, src net.Destination, dst net.Destination) error
	// refusePacket tells the system that what src sent to dst was refused, quoting the headers of a datagram
	// of the flow. Without it nothing is told
	refusePacket func(quote []byte, src net.Destination, dst net.Destination) error
}

func newUdpConnectionHandler(handleConnection func(conn net.Conn, dest net.Destination), writePacket func(data []byte, src net.Destination, dst net.Destination) error) *udpConnectionHandler {
	handler := &udpConnectionHandler{
		udpConns:         make(map[udpFlow]*udpConn),
		handleConnection: handleConnection,
		writePacket:      writePacket,
	}

	return handler
}

// HandlePacket handles UDP packets coming from tun, to forward to the dispatcher.
// Returning packets keep their own source through the UDP metadata of WriteMultiBuffer (FullCone NAT),
// while every destination of a source has a connection, and so a route, of its own
func (u *udpConnectionHandler) HandlePacket(src net.Destination, dst net.Destination, data *buf.Buffer) {
	u.HandleRefusablePacket(src, dst, data, nil)
}

// HandleRefusablePacket is HandlePacket for a datagram whose flow may be refused (udpConn.RejectUDP): quote is
// its IP and UDP headers, copied if the datagram opens the flow, or nil
func (u *udpConnectionHandler) HandleRefusablePacket(src net.Destination, dst net.Destination, data *buf.Buffer, quote []byte) {
	data.UDP = &dst
	flow := udpFlow{src: src, dst: dst}

	u.RLock()
	conn, found := u.udpConns[flow]
	if found {
		if !conn.queue.push(data) {
			errors.LogDebug(context.Background(), "drop udp with size ", data.Len(), " to ", dst.NetAddr(), " original ", conn.dst.NetAddr(), " > queue full")
			data.Release()
		}
		u.RUnlock()
		return
	}
	u.RUnlock()

	u.Lock()
	defer u.Unlock()

	if u.closed {
		data.Release()
		return
	}
	conn, found = u.udpConns[flow]
	if !found {
		conn = &udpConn{handler: u, queue: newPacketQueue(udpQueueLimit), src: src, dst: dst}
		if quote != nil {
			// only the headers, never what the datagram carries
			conn.quote = bytes.Clone(quote)
		}
		if dst.Port == 443 && dst.Address.Family().IsIPv4() {
			udp443Attempts.Add(1)
		}
		u.udpConns[flow] = conn

		go u.handleConnection(conn, dst)
	}

	// queue the packet for the reader of the connection, or discard it
	if !conn.queue.push(data) {
		errors.LogDebug(context.Background(), "drop udp with size ", data.Len(), " to ", dst.NetAddr(), " original ", conn.dst.NetAddr(), " > queue full 2")
		data.Release()
	}
}

// closeAll ends every flow when the stack closes: no packet comes for them any more, and a flow left waiting for
// one would keep its connection, and through its context the dispatcher and the whole closed instance, until the
// idle timeout (Xray's own process ends with its instance; an app that restarts the instance would collect them)
func (u *udpConnectionHandler) closeAll() {
	u.Lock()
	conns := u.udpConns
	u.udpConns = make(map[udpFlow]*udpConn)
	u.closed = true
	u.Unlock()
	for _, conn := range conns {
		conn.queue.close()
	}
}

func (u *udpConnectionHandler) connectionFinished(conn *udpConn) {
	flow := udpFlow{src: conn.src, dst: conn.dst}
	u.Lock()
	// Close runs twice per flow; a newer conn may already own this flow.
	if u.udpConns[flow] == conn {
		delete(u.udpConns, flow)
		conn.queue.close()
	}
	u.Unlock()
}

// udp connection abstraction
type udpConn struct {
	handler *udpConnectionHandler

	queue *packetQueue
	src   net.Destination
	dst   net.Destination
	// quote is the IP and UDP headers of the first datagram, for RejectUDP; nil if the flow is not refused that way
	quote      []byte
	rejectOnce sync.Once
}

var udp443Attempts, rejectedUDP443 atomic.Int64

// UDP443Attempts counts new IPv4 UDP/443 TUN associations for this process.
// Associations are keyed by source and destination, not individual packets.
func UDP443Attempts() int64 { return udp443Attempts.Load() }

// RejectedUDP443 counts successfully emitted local IPv4 port-unreachable replies.
func RejectedUDP443() int64 { return rejectedUDP443.Load() }

// RejectUDP tells the application at once that its flow is refused (session.RejectUDP), once at most
func (c *udpConn) RejectUDP() {
	c.rejectOnce.Do(func() {
		if c.quote == nil || c.handler.refusePacket == nil {
			return
		}
		if c.handler.refusePacket(c.quote, c.src, c.dst) == nil && c.dst.Port == 443 && c.dst.Address.Family().IsIPv4() {
			rejectedUDP443.Add(1)
		}
	})
}

func (c *udpConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b, ok := c.queue.pop()
	if !ok {
		return nil, io.EOF
	}
	return buf.MultiBuffer{b}, nil
}

// Read packets from the connection
func (c *udpConn) Read(p []byte) (int, error) {
	b, ok := c.queue.pop()
	if !ok {
		return 0, io.EOF
	}
	defer b.Release()
	n := copy(p, b.Bytes())
	if n != int(b.Len()) {
		return 0, io.ErrShortBuffer
	}
	return n, nil
}

func (c *udpConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for i, b := range mb {
		dst := c.dst
		if b.UDP != nil {
			if b.UDP.Address.Family().IsDomain() {
				errors.LogError(context.Background(), "impossible domain packet ", b.UDP, " reply via original target ", dst)
			} else {
				dst = *b.UDP
			}
		}
		err := c.handler.writePacket(b.Bytes(), dst, c.src)
		if err != nil {
			buf.ReleaseMulti(mb[i:])
			return err
		}
		b.Release()
	}
	return nil
}

// Write returning packets back
func (c *udpConn) Write(p []byte) (int, error) {
	// sending packets back mean sending payload with source/destination reversed
	err := c.handler.writePacket(p, c.dst, c.src)
	if err != nil {
		return 0, err
	}

	return len(p), nil
}

func (c *udpConn) Close() error {
	c.handler.connectionFinished(c)

	return nil
}

func (c *udpConn) LocalAddr() net.Addr {
	return c.dst.RawNetAddr()
}

func (c *udpConn) RemoteAddr() net.Addr {
	return c.src.RawNetAddr()
}

func (c *udpConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *udpConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *udpConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// udpQueueLimit bounds the packets waiting for one UDP flow; more are dropped.
const udpQueueLimit = 1024

// packetQueue holds the packets waiting for one UDP flow. Unlike a buffered
// channel of the same bound it only allocates for packets actually queued, so
// the many idle flows kept until the idle timeout cost next to nothing.
type packetQueue struct {
	mu     sync.Mutex
	items  []*buf.Buffer
	limit  int
	notify chan struct{}
	closed bool
}

func newPacketQueue(limit int) *packetQueue {
	return &packetQueue{limit: limit, notify: make(chan struct{}, 1)}
}

// push queues b and reports whether it was accepted.
func (q *packetQueue) push(b *buf.Buffer) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || len(q.items) >= q.limit {
		return false
	}
	q.items = append(q.items, b)
	select {
	case q.notify <- struct{}{}:
	default:
	}
	return true
}

// pop blocks until a packet is queued or the queue is closed and drained.
func (q *packetQueue) pop() (*buf.Buffer, bool) {
	for {
		q.mu.Lock()
		if len(q.items) > 0 {
			b := q.items[0]
			q.items[0] = nil
			q.items = q.items[1:]
			if len(q.items) == 0 {
				q.items = nil
			}
			q.mu.Unlock()
			return b, true
		}
		if q.closed {
			q.mu.Unlock()
			return nil, false
		}
		q.mu.Unlock()
		<-q.notify
	}
}

func (q *packetQueue) close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.closed {
		q.closed = true
		close(q.notify)
	}
}
