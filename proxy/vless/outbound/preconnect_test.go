package outbound

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type trackedConn struct {
	net.Conn
	closed atomic.Int32
}

func (c *trackedConn) Close() error { c.closed.Add(1); return nil }

// Without a connection of its own a trackedConn is open and silent: the liveness
// check's short read times out, as on a live spare.
func (c *trackedConn) SetReadDeadline(t time.Time) error {
	if c.Conn != nil {
		return c.Conn.SetReadDeadline(t)
	}
	return nil
}
func (c *trackedConn) Read(b []byte) (int, error) {
	if c.Conn != nil {
		return c.Conn.Read(b)
	}
	return 0, os.ErrDeadlineExceeded
}
func eventually(t *testing.T, f func() bool) {
	t.Helper()
	end := time.Now().Add(time.Second)
	for time.Now().Before(end) {
		if f() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition did not become true")
}
func readyCount(p *preconnectPool) int { p.mu.Lock(); defer p.mu.Unlock(); return len(p.ready) }

func TestPreconnectEmptyNeverWaitsAndCapsExtraDials(t *testing.T) {
	var calls atomic.Int32
	p := newPreconnectPool(100, func(ctx context.Context) (stat.Connection, error) { calls.Add(1); <-ctx.Done(); return nil, ctx.Err() })
	defer p.Close()
	started := time.Now()
	for i := 0; i < 20; i++ {
		if p.Take() != nil {
			t.Fatal("unexpected spare")
		}
	}
	if time.Since(started) > 100*time.Millisecond {
		t.Fatal("empty pool delayed request fallback")
	}
	eventually(t, func() bool { return calls.Load() == 2 })
}
func TestPreconnectExpiryClosesWithoutIdleRefill(t *testing.T) {
	var calls atomic.Int32
	conn := &trackedConn{}
	p := newPreconnectPool(1, func(context.Context) (stat.Connection, error) { calls.Add(1); return conn, nil })
	p.policy = preconnectPolicy{ttlMin: 30 * time.Millisecond, ttlMax: 30 * time.Millisecond}
	defer p.Close()
	p.Take()
	eventually(t, func() bool { return readyCount(p) == 1 })
	eventually(t, func() bool { return conn.closed.Load() == 1 })
	time.Sleep(50 * time.Millisecond)
	if readyCount(p) != 0 || calls.Load() != 1 {
		t.Fatal("expired idle pool refilled without demand")
	}
}
func TestPreconnectTakeTransfersOwnership(t *testing.T) {
	ch := make(chan *trackedConn, 4)
	p := newPreconnectPool(1, func(context.Context) (stat.Connection, error) { c := &trackedConn{}; ch <- c; return c, nil })
	p.Take()
	first := <-ch
	eventually(t, func() bool { return readyCount(p) == 1 })
	got := p.Take()
	if got != first {
		t.Fatal("ready connection not returned")
	}
	second := <-ch
	eventually(t, func() bool { return readyCount(p) == 1 })
	p.Close()
	if first.closed.Load() != 0 || second.closed.Load() != 1 {
		t.Fatal("close touched leased socket or leaked queued spare")
	}
	got.Close()
}
func TestPreconnectCloseCancelsAndDrainsConcurrentFills(t *testing.T) {
	var canceled atomic.Int32
	p := newPreconnectPool(2, func(ctx context.Context) (stat.Connection, error) {
		<-ctx.Done()
		canceled.Add(1)
		return &trackedConn{}, ctx.Err()
	})
	p.Take()
	p.Close()
	p.Close()
	if canceled.Load() != 2 || readyCount(p) != 0 || p.Take() != nil {
		t.Fatal("pool did not cancel/drain or restarted after close")
	}
}
func TestPreconnectFailureBackoffAndDemandOnlyRetry(t *testing.T) {
	var calls atomic.Int32
	p := newPreconnectPool(1, func(context.Context) (stat.Connection, error) { calls.Add(1); return nil, errors.New("offline") })
	defer p.Close()
	p.Take()
	eventually(t, func() bool { p.mu.Lock(); defer p.mu.Unlock(); return p.failures == 1 })
	for i := 0; i < 20; i++ {
		p.Take()
	}
	if calls.Load() != 1 {
		t.Fatal("failed dial retried without cooldown")
	}
	time.Sleep(preconnectBackoff + 30*time.Millisecond)
	if calls.Load() != 1 {
		t.Fatal("idle retry burned bandwidth")
	}
	p.Take()
	eventually(t, func() bool { return calls.Load() == 2 })
}
func TestPreconnectDialDeadline(t *testing.T) {
	stopped := make(chan struct{})
	p := newPreconnectPool(1, func(ctx context.Context) (stat.Connection, error) {
		<-ctx.Done()
		close(stopped)
		return nil, ctx.Err()
	})
	p.dialTimeout = 20 * time.Millisecond
	defer p.Close()
	p.Take()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("background dial had no deadline")
	}
}

// TLS Close may wait to send close_notify; discarding an unused reserve must
// bypass that path so expiration cannot block an unrelated request's fallback.
type slowTLSClose struct {
	*trackedConn
	gracefulCalls atomic.Int32
	unblock       chan struct{}
}

func (c *slowTLSClose) NetConn() net.Conn { return c.trackedConn }
func (c *slowTLSClose) Close() error      { c.gracefulCalls.Add(1); return nil }

func TestPreconnectDiscardClosesRawTLSWithoutGracefulWait(t *testing.T) {
	conn := &slowTLSClose{trackedConn: &trackedConn{}, unblock: make(chan struct{})}
	p := newPreconnectPool(1, func(ctx context.Context) (stat.Connection, error) { <-ctx.Done(); return nil, ctx.Err() })
	defer func() { close(conn.unblock); p.Close() }()
	// Simulate a stale spare whose expiry callback has not yet run. Take must
	// discard it and fall back immediately even if graceful Close would hang.
	p.ready = []*preconnectSpare{{conn: &stat.CounterConnection{Connection: conn}, expires: time.Now().Add(-time.Second), timer: time.AfterFunc(time.Hour, func() {})}}
	result := make(chan stat.Connection, 1)
	go func() { result <- p.Take() }()
	select {
	case got := <-result:
		if got != nil {
			t.Fatal("expired connection was leased")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("graceful TLS close blocked request fallback")
	}
	if conn.gracefulCalls.Load() != 0 || conn.closed.Load() != 1 {
		t.Fatal("reserve discard did not close raw TLS transport directly")
	}
}

type reservePolicyDialer struct {
	fresh, health, reserve atomic.Int32
}

func (d *reservePolicyDialer) Dial(ctx context.Context, _ xnet.Destination) (stat.Connection, error) {
	if session.IsPreconnect(ctx) {
		d.reserve.Add(1)
	} else {
		d.fresh.Add(1)
		if session.IsPreconnectDisabled(ctx) {
			d.health.Add(1)
		}
	}
	// Stop Process after its connection choice at Vision's TLS type check. This
	// isolates the real reserve/dial decision without network traffic or retries.
	return &trackedConn{}, nil
}
func (*reservePolicyDialer) DestIpAddress() xnet.IP                                { return nil }
func (*reservePolicyDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

func TestHealthDialLeavesColdAndWarmAppReservesUntouched(t *testing.T) {
	h := &Handler{testpre: 2, server: &protocol.ServerSpec{
		Destination: xnet.TCPDestination(xnet.ParseAddress("198.51.100.1"), 2083),
		User:        &protocol.MemoryUser{Account: &vless.MemoryAccount{Flow: vless.XRV}},
	}}
	defer h.Close()
	d := &reservePolicyDialer{}
	process := func(health bool) {
		t.Helper()
		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
			Target: xnet.TCPDestination(xnet.DomainAddress("www.youtube.com"), 443),
		}})
		if health {
			ctx = session.ContextWithPreconnectDisabled(ctx)
		}
		if err := h.Process(ctx, &transport.Link{}, d); err == nil || !strings.Contains(err.Error(), "XTLS only supports TLS and REALITY") {
			t.Fatalf("did not stop at the expected post-dial Vision boundary: %v", err)
		}
	}

	process(true)
	if d.fresh.Load() != 1 || d.health.Load() != 1 || d.reserve.Load() != 0 || h.prePool != nil {
		t.Fatalf("cold health call warmed reserve: fresh=%d health=%d reserve=%d pool=%v", d.fresh.Load(), d.health.Load(), d.reserve.Load(), h.prePool != nil)
	}

	// Ordinary app demand still creates its two bounded spares.
	process(false)
	p := h.prePool
	if p == nil {
		t.Fatal("app demand did not initialize its reserve")
	}
	eventually(t, func() bool { return readyCount(p) == 2 })
	if d.fresh.Load() != 2 || d.reserve.Load() != 2 {
		t.Fatalf("unexpected app demand dials: fresh=%d reserve=%d", d.fresh.Load(), d.reserve.Load())
	}
	p.mu.Lock()
	first, second := p.ready[0], p.ready[1]
	p.mu.Unlock()
	hits, misses := PreconnectHits(), PreconnectMisses()

	process(true)
	p.mu.Lock()
	untouched := len(p.ready) == 2 && p.ready[0] == first && p.ready[1] == second && p.inFlight == 0
	p.mu.Unlock()
	if !untouched || d.fresh.Load() != 3 || d.health.Load() != 2 || d.reserve.Load() != 2 || PreconnectHits() != hits || PreconnectMisses() != misses {
		t.Fatal("warm health call consumed/refilled app reserves or entered their metrics")
	}

	// The next actual app request takes the original first spare, then refills.
	process(false)
	eventually(t, func() bool { return readyCount(p) == 2 })
	if PreconnectHits() != hits+1 || d.fresh.Load() != 3 || d.reserve.Load() != 3 || first.conn.(*trackedConn).closed.Load() != 1 || second.conn.(*trackedConn).closed.Load() != 0 {
		t.Fatal("app reserve ownership/refill changed after health call")
	}
}

// A spare whose reads are scripted: what the liveness check would find on its socket.
type scriptedConn struct {
	trackedConn
	read func([]byte) (int, error)
}

func (c *scriptedConn) Read(b []byte) (int, error) { return c.read(b) }

func readySpare(c stat.Connection) *preconnectSpare {
	return &preconnectSpare{conn: c, expires: time.Now().Add(time.Hour), timer: time.AfterFunc(time.Hour, func() {})}
}

func TestPreconnectLifetimeSpreadsInsidePolicy(t *testing.T) {
	p := newPreconnectPool(1, nil)
	defer p.Close()
	p.policy = preconnectPolicy{ttlMin: 20 * time.Second, ttlMax: 40 * time.Second}
	lo, hi := time.Hour, time.Duration(0)
	for i := 0; i < 2000; i++ {
		d := p.lifetime()
		if d < 20*time.Second || d > 40*time.Second {
			t.Fatalf("lifetime %v outside 20-40 s", d)
		}
		lo, hi = min(lo, d), max(hi, d)
	}
	if lo > 22*time.Second || hi < 38*time.Second {
		t.Fatalf("lifetimes not spread over the range: %v-%v", lo, hi)
	}
}

func TestPreconnectStaleSparesFallBackInsteadOfFailing(t *testing.T) {
	p := newPreconnectPool(2, func(ctx context.Context) (stat.Connection, error) { <-ctx.Done(); return nil, ctx.Err() })
	defer p.Close()
	p.policy = preconnectPolicy{ttlMin: time.Hour, ttlMax: time.Hour, check: 5 * time.Millisecond}
	hungUp := &scriptedConn{read: func([]byte) (int, error) { return 0, io.EOF }}
	live := &trackedConn{}
	stale, hits, misses := PreconnectStale(), PreconnectHits(), PreconnectMisses()
	p.ready = []*preconnectSpare{readySpare(hungUp), readySpare(live)}
	if got := p.Take(); got != live {
		t.Fatal("the live spare was not used after the closed one")
	}
	if hungUp.closed.Load() != 1 || live.closed.Load() != 0 || PreconnectStale() != stale+1 || PreconnectHits() != hits+1 {
		t.Fatal("the closed spare was not discarded and counted as stale")
	}

	// Every spare closed (one hung up, one already sending data): the request
	// gets no spare at once and dials normally.
	spoke := &scriptedConn{read: func(b []byte) (int, error) { b[0] = 0x17; return 1, nil }}
	reset := &scriptedConn{read: func([]byte) (int, error) { return 0, errors.New("connection reset by peer") }}
	p.mu.Lock()
	p.ready = []*preconnectSpare{readySpare(spoke), readySpare(reset)}
	p.mu.Unlock()
	started := time.Now()
	if p.Take() != nil {
		t.Fatal("a closed spare was leased")
	}
	if time.Since(started) > 100*time.Millisecond {
		t.Fatal("checking closed spares delayed the request's own dial")
	}
	if spoke.closed.Load() != 1 || reset.closed.Load() != 1 || PreconnectStale() != stale+3 || PreconnectMisses() != misses+1 {
		t.Fatal("closed spares were not all discarded, or the miss was not counted once")
	}
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// The check must read through TLS: a TLS 1.3 server sends session tickets after
// the handshake (REALITY copies the real site's), so bytes are waiting on an
// idle spare's socket. Those must not count as "closed", the check must leave the
// connection usable, and a server hang-up must be seen.
func TestPreconnectCheckReadsThroughTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cert := selfSignedCert(t)
	accepted := make(chan *tls.Conn, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		s := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
		if s.Handshake() == nil {
			accepted <- s
		}
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	defer c.Close()
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	s := <-accepted
	time.Sleep(50 * time.Millisecond) // the server's tickets are now waiting on the client's socket

	if !preconnectAlive(c, 5*time.Millisecond) {
		t.Fatal("an open TLS connection with pending session tickets was judged closed")
	}
	go func() {
		got := make([]byte, 5)
		if _, err := io.ReadFull(s, got); err == nil && string(got) == "hello" {
			s.Write([]byte("reply"))
		}
	}()
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal("write after the check:", err)
	}
	c.SetReadDeadline(time.Now().Add(time.Second))
	reply := make([]byte, 5)
	if _, err := io.ReadFull(c, reply); err != nil || string(reply) != "reply" {
		t.Fatalf("connection not usable after the check: %q %v", reply, err)
	}
	c.SetReadDeadline(time.Time{})

	s.Close() // as at the server's handshake timeout
	eventually(t, func() bool { return !preconnectAlive(c, 5*time.Millisecond) })
}

func TestPreconnectWarmWindowRefillsOnlyAfterRecentDemand(t *testing.T) {
	var calls atomic.Int32
	p := newPreconnectPool(1, func(context.Context) (stat.Connection, error) { calls.Add(1); return &trackedConn{}, nil })
	defer p.Close()
	p.policy = preconnectPolicy{ttlMin: 20 * time.Millisecond, ttlMax: 20 * time.Millisecond, warm: 150 * time.Millisecond}
	p.Take()
	eventually(t, func() bool { return calls.Load() >= 3 }) // replaced at expiry while the request is recent
	time.Sleep(250 * time.Millisecond)                      // past the window: the last spare expires unreplaced
	settled := calls.Load()
	time.Sleep(100 * time.Millisecond)
	if calls.Load() != settled || readyCount(p) != 0 {
		t.Fatalf("idle pool kept dialing after the warm window: %d -> %d, ready %d", settled, calls.Load(), readyCount(p))
	}
}
