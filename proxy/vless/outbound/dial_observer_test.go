package outbound

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type failingDialer struct{ reservePolicyDialer }

func (*failingDialer) Dial(context.Context, xnet.Destination) (stat.Connection, error) {
	return nil, errors.New("connection refused")
}

func TestDialObserverSeesEveryServerDialOnce(t *testing.T) {
	type seen struct{ reserve, health, failed bool }
	var mu sync.Mutex
	var dials []seen
	SetDialObserver(func(ctx context.Context, err error) {
		mu.Lock()
		dials = append(dials, seen{session.IsPreconnect(ctx), session.IsPreconnectDisabled(ctx), err != nil})
		mu.Unlock()
	})
	defer SetDialObserver(nil)
	count := func(want seen) (n int) {
		mu.Lock()
		defer mu.Unlock()
		for _, d := range dials {
			if d == want {
				n++
			}
		}
		return n
	}

	h := &Handler{testpre: 2, server: &protocol.ServerSpec{
		Destination: xnet.TCPDestination(xnet.ParseAddress("198.51.100.1"), 443),
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
		// Stops right after its dial (see TestHealthDialLeavesColdAndWarmAppReservesUntouched).
		if err := h.Process(ctx, &transport.Link{}, d); err == nil || !strings.Contains(err.Error(), "XTLS only supports TLS and REALITY") {
			t.Fatalf("did not stop at the expected post-dial Vision boundary: %v", err)
		}
	}
	process(true)
	process(false)
	eventually(t, func() bool { return count(seen{reserve: true}) == 2 })
	if count(seen{health: true}) != 1 || count(seen{}) != 1 || int(d.fresh.Load()+d.reserve.Load()) != 4 {
		t.Fatalf("observed %v for fresh=%d reserve=%d", dials, d.fresh.Load(), d.reserve.Load())
	}

	// A failed dial is reported with its error, once per attempt.
	if _, err := h.dialServer(context.Background(), &failingDialer{}); err == nil || count(seen{failed: true}) != 1 {
		t.Fatalf("failed dial not observed once: %v %v", err, dials)
	}

	SetDialObserver(nil)
	total := func() int { mu.Lock(); defer mu.Unlock(); return len(dials) }
	before := total()
	if _, err := h.dialServer(context.Background(), &failingDialer{}); err == nil || total() != before {
		t.Fatal("a removed observer was still called")
	}
}
