package blackhole_test

import (
	"context"
	"runtime"
	"testing"
	"time"
	"weak"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy/blackhole"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type heldKey struct{}

type held struct{ _ [1 << 16]byte }

// blockUDP starts a blocked UDP flow (multicast DNS, say) and returns what Process returned, and a weak pointer to
// a value only the flow's context holds.
func blockUDP(t *testing.T, handler *blackhole.Handler) (<-chan error, weak.Pointer[held]) {
	t.Helper()
	value := &held{}
	alive := weak.Make(value)
	ctx := context.WithValue(context.Background(), heldKey{}, value)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: net.UDPDestination(net.IPAddress([]byte{224, 0, 0, 251}), 5353)}})
	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("query"))}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- handler.Process(ctx, &transport.Link{Reader: reader, Writer: writer}, nil) }()
	return done, alive
}

// Closing the instance ends every blocked UDP flow at once. A flow waits 30 to 90 s of inactivity to swallow what
// else comes, and closing did not end that wait: on Android, which restarts the instance in its process on every
// reconnect and server move, each blocked UDP flow open at the stop (multicast or LAN discovery into the tunnel)
// kept the closed instance, about 7 MB, until then.
func TestCloseEndsBlockedUDPFlows(t *testing.T) {
	handler, err := blackhole.New(context.Background(), &blackhole.Config{})
	common.Must(err)
	done, alive := blockUDP(t, handler)
	select {
	case <-done:
		t.Fatal("a blocked UDP flow ended while the handler was open")
	case <-time.After(200 * time.Millisecond):
	}

	common.Must(common.Close(handler))
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the blocked UDP flow outlived the closed handler")
	}
	// Nothing holds the ended flow's context either: the inactivity timer kept it, and through it the instance,
	// until the timer fired
	for deadline := time.Now().Add(2 * time.Second); alive.Value() != nil; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the ended flow's context is still held")
		}
		runtime.GC()
	}

	// A flow that opens during the stop ends at once too
	late, _ := blockUDP(t, handler)
	select {
	case <-late:
	case <-time.After(time.Second):
		t.Fatal("a blocked UDP flow opened after the close kept waiting")
	}
}
