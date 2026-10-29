package outbound

import (
	"context"
	"errors"
	"github.com/xtls/xray-core/transport/internet/stat"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type trackedConn struct {
	net.Conn
	closed atomic.Int32
}

func (c *trackedConn) Close() error { c.closed.Add(1); return nil }
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
	p.ttl = 30 * time.Millisecond
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
