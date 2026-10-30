package outbound

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	xctx "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// A demand-driven reserve, never a connection multiplexer. At most two extra
// connections can be dialing/idle. Idle expiry never replenishes the reserve.
// Two seconds is deliberately below even the historical four-second server
// VLESS-header timeout. No application payload is sent until a caller takes it.
const (
	preconnectMax         = 2
	preconnectTTL         = 2 * time.Second
	preconnectDialTimeout = 3 * time.Second
	preconnectBackoff     = 250 * time.Millisecond
)

var preconnectHits, preconnectMisses, preconnectDials atomic.Int64

// Aggregate process-lifetime counters, without browsing destinations or payloads.
func PreconnectHits() int64   { return preconnectHits.Load() }
func PreconnectMisses() int64 { return preconnectMisses.Load() }
func PreconnectDials() int64  { return preconnectDials.Load() }

type preconnectSpare struct {
	conn    stat.Connection
	expires time.Time
	timer   *time.Timer
}

type preconnectPool struct {
	mu               sync.Mutex
	ctx              context.Context
	cancel           context.CancelFunc
	dial             func(context.Context) (stat.Connection, error)
	limit            int
	ttl, dialTimeout time.Duration
	ready            []*preconnectSpare
	inFlight         int
	failures         uint
	nextTry          time.Time
	closed           bool
	wg               sync.WaitGroup
}

func newPreconnectPool(limit int, dial func(context.Context) (stat.Connection, error)) *preconnectPool {
	if limit > preconnectMax {
		limit = preconnectMax
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &preconnectPool{ctx: ctx, cancel: cancel, dial: dial, limit: limit, ttl: preconnectTTL, dialTimeout: preconnectDialTimeout}
}

// Take returns immediately when the reserve is empty; callers use their normal
// request-context dial. Only demand calls can create work, with a bounded retry
// cooldown after errors. Timer callbacks only discard stale idle connections.
func (p *preconnectPool) Take() stat.Connection {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	now := time.Now()
	var conn stat.Connection
	for len(p.ready) > 0 {
		spare := p.ready[0]
		p.ready = p.ready[1:]
		spare.timer.Stop()
		if now.Before(spare.expires) {
			conn = spare.conn
			break
		}
		discardPreconnect(spare.conn)
	}
	if !now.Before(p.nextTry) {
		for len(p.ready)+p.inFlight < p.limit {
			p.inFlight++
			p.wg.Add(1)
			go p.fill()
		}
	}
	if conn != nil {
		preconnectHits.Add(1)
	} else {
		preconnectMisses.Add(1)
	}
	return conn
}

func (p *preconnectPool) fill() {
	defer p.wg.Done()
	ctx, cancel := context.WithTimeout(p.ctx, p.dialTimeout)
	preconnectDials.Add(1)
	conn, err := p.dial(ctx)
	cancel()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.inFlight--
	if err != nil || p.closed {
		if conn != nil {
			discardPreconnect(conn)
		}
		if err != nil && !p.closed {
			if p.failures < 5 {
				p.failures++
			}
			p.nextTry = time.Now().Add(preconnectBackoff * time.Duration(1<<(p.failures-1)))
		}
		return
	}
	p.failures = 0
	p.nextTry = time.Time{}
	spare := &preconnectSpare{conn: conn, expires: time.Now().Add(p.ttl)}
	p.ready = append(p.ready, spare)
	spare.timer = time.AfterFunc(p.ttl, func() { p.expire(spare) })
}

func (p *preconnectPool) expire(spare *preconnectSpare) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, s := range p.ready {
		if s == spare {
			p.ready = append(p.ready[:i], p.ready[i+1:]...)
			discardPreconnect(s.conn)
			return
		}
	}
}

// A reserve has never carried application data. Close the raw TLS transport
// directly: TLS close_notify may block for five seconds and must not stall the
// pool lock or a request falling back to its normal dial.
func discardPreconnect(conn stat.Connection) {
	conn = stat.TryUnwrapStatsConn(conn)
	if conn == nil {
		return
	}
	if tlsConn, ok := conn.(interface{ NetConn() net.Conn }); ok {
		conn = tlsConn.NetConn()
	}
	conn.Close()
}

func (p *preconnectPool) Close() {
	p.mu.Lock()
	p.closed = true
	p.cancel()
	for _, spare := range p.ready {
		spare.timer.Stop()
		discardPreconnect(spare.conn)
	}
	p.ready = nil
	p.mu.Unlock()
	// No worker can be added after closed is set under mu. Real TCP/REALITY
	// dialing honors this cancellation; wait for owned sockets to be released.
	p.wg.Wait()
}

func (h *Handler) takePreconnect(ctx context.Context, dialer internet.Dialer) stat.Connection {
	// Health checks must test a new connection without stealing a warm app spare
	// or manufacturing app demand that would refill an otherwise idle reserve.
	if session.IsPreconnectDisabled(ctx) {
		return nil
	}
	h.preMu.Lock()
	if h.preClosed {
		h.preMu.Unlock()
		return nil
	}
	if h.prePool == nil {
		// The pool owns its lifetime. Preserve gateway/source routing values in a
		// private session, never mutable per-request Outbound pointers or cancellation.
		outbounds := session.OutboundsFromContext(ctx)
		var template session.Outbound
		if len(outbounds) > 0 {
			template.Gateway = outbounds[len(outbounds)-1].Gateway
		}
		template.Name = "vless"
		template.Target = h.server.Destination
		var inbound *session.Inbound
		if in := session.InboundFromContext(ctx); in != nil {
			inbound = &session.Inbound{Source: in.Source, Local: in.Local}
		}
		h.prePool = newPreconnectPool(int(h.testpre), func(ctx context.Context) (stat.Connection, error) {
			ob := template
			ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{&ob})
			if inbound != nil {
				copy := *inbound
				ctx = session.ContextWithInbound(ctx, &copy)
			}
			ctx = xctx.ContextWithID(ctx, session.NewID())
			ctx = session.ContextWithPreconnect(ctx)
			return dialer.Dial(ctx, h.server.Destination)
		})
	}
	pool := h.prePool
	h.preMu.Unlock()
	return pool.Take()
}
