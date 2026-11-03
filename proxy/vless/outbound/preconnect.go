package outbound

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
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
// connections can be dialing/idle, and each carries exactly one request with
// Vision as usual. No application payload is sent until a caller takes it.
// How long a spare may wait, whether it is checked before use and whether an
// expiring spare is replaced come from preconnectBuildPolicy (preconnect_policy.go).
const (
	preconnectMax         = 2
	preconnectDialTimeout = 3 * time.Second
	preconnectBackoff     = 250 * time.Millisecond
)

// Servers close a connection that sends no VLESS request within their handshake
// timeout: 60 s on Xray v26.10.31 (measured on production 2026-11-03: 59.4 s
// Singapore, 59.9 s Tokyo), 4 s on older servers. A spare must be used or dropped
// well before that; the check catches a server that hung up earlier anyway.
type preconnectPolicy struct {
	ttlMin, ttlMax time.Duration // each spare's lifetime, chosen at random in [ttlMin, ttlMax]
	check          time.Duration // >0: before use, read through TLS this long to find a closed spare
	warm           time.Duration // >0: replace an expiring spare while the last real request is this recent
}

var preconnectHits, preconnectMisses, preconnectDials, preconnectStale atomic.Int64

// Aggregate process-lifetime counters, without browsing destinations or payloads.
func PreconnectHits() int64   { return preconnectHits.Load() }
func PreconnectMisses() int64 { return preconnectMisses.Load() }
func PreconnectDials() int64  { return preconnectDials.Load() }

// PreconnectStale counts spares found closed by the server when a request wanted them.
func PreconnectStale() int64 { return preconnectStale.Load() }

// PreconnectPolicy names this build's reserve policy for logs, e.g. "trial 20s-40s check 2ms warm 0s".
func PreconnectPolicy() string {
	p := preconnectBuildPolicy
	return fmt.Sprintf("%s %v-%v check %v warm %v", preconnectPolicyName, p.ttlMin, p.ttlMax, p.check, p.warm)
}

type preconnectSpare struct {
	conn    stat.Connection
	expires time.Time
	timer   *time.Timer
}

type preconnectPool struct {
	mu          sync.Mutex
	ctx         context.Context
	cancel      context.CancelFunc
	dial        func(context.Context) (stat.Connection, error)
	limit       int
	policy      preconnectPolicy
	dialTimeout time.Duration
	ready       []*preconnectSpare
	inFlight    int
	failures    uint
	nextTry     time.Time
	lastDemand  time.Time
	closed      bool
	wg          sync.WaitGroup
}

func newPreconnectPool(limit int, dial func(context.Context) (stat.Connection, error)) *preconnectPool {
	if limit > preconnectMax {
		limit = preconnectMax
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &preconnectPool{ctx: ctx, cancel: cancel, dial: dial, limit: limit, policy: preconnectBuildPolicy, dialTimeout: preconnectDialTimeout}
}

// lifetime spreads spares over [ttlMin, ttlMax] so their closes do not tick at a fixed interval.
func (p *preconnectPool) lifetime() time.Duration {
	if spread := p.policy.ttlMax - p.policy.ttlMin; spread > 0 {
		return p.policy.ttlMin + rand.N(spread+1)
	}
	return p.policy.ttlMin
}

// Take returns immediately when the reserve is empty; callers use their normal
// request-context dial. Only demand calls can create work, with a bounded retry
// cooldown after errors. A spare the server already closed is discarded and the
// next one tried, so a stale spare never fails the request: at worst it dials.
func (p *preconnectPool) Take() stat.Connection {
	refilled := false
	for {
		spare, ok := p.pop(!refilled)
		refilled = true
		if !ok {
			return nil
		}
		if spare == nil {
			preconnectMisses.Add(1)
			return nil
		}
		if p.policy.check > 0 && !preconnectAlive(spare.conn, p.policy.check) {
			preconnectStale.Add(1)
			discardPreconnect(spare.conn)
			continue
		}
		preconnectHits.Add(1)
		return spare.conn
	}
}

// pop removes the first unexpired spare (nil when there is none) and, once per
// request, starts refills up to the limit. ok is false after Close.
func (p *preconnectPool) pop(demand bool) (spare *preconnectSpare, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, false
	}
	now := time.Now()
	for len(p.ready) > 0 {
		s := p.ready[0]
		p.ready = p.ready[1:]
		s.timer.Stop()
		if now.Before(s.expires) {
			spare = s
			break
		}
		discardPreconnect(s.conn)
	}
	if demand {
		p.lastDemand = now
		p.refillLocked(now)
	}
	return spare, true
}

func (p *preconnectPool) refillLocked(now time.Time) {
	if now.Before(p.nextTry) {
		return
	}
	for len(p.ready)+p.inFlight < p.limit {
		p.inFlight++
		p.wg.Add(1)
		go p.fill()
	}
}

// preconnectAlive reports whether an unused spare is still open. It reads through
// the TLS layer, which consumes the server's post-handshake records (REALITY sends
// them as the real site would); a raw-socket peek would either eat those bytes or
// hide a close behind them. A read that times out leaves a TLS connection usable.
// A VLESS server never speaks first, so any data, EOF or other error means closed.
func preconnectAlive(conn stat.Connection, wait time.Duration) bool {
	if conn.SetReadDeadline(time.Now().Add(wait)) != nil {
		return false
	}
	var one [1]byte
	n, err := conn.Read(one[:])
	var timeout net.Error
	if n > 0 || !errors.As(err, &timeout) || !timeout.Timeout() {
		return false
	}
	return conn.SetReadDeadline(time.Time{}) == nil
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
	life := p.lifetime()
	spare := &preconnectSpare{conn: conn, expires: time.Now().Add(life)}
	p.ready = append(p.ready, spare)
	spare.timer = time.AfterFunc(life, func() { p.expire(spare) })
}

// expire drops an unused spare at the end of its lifetime. It is replaced only
// inside the policy's warm window after a real request (never in normal builds),
// so an idle device stops making connections once that window has passed.
func (p *preconnectPool) expire(spare *preconnectSpare) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, s := range p.ready {
		if s == spare {
			p.ready = append(p.ready[:i], p.ready[i+1:]...)
			discardPreconnect(s.conn)
			if now := time.Now(); !p.closed && p.policy.warm > 0 && now.Sub(p.lastDemand) < p.policy.warm {
				p.refillLocked(now)
			}
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
