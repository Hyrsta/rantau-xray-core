package tun

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
)

// countingStack is a Stack that counts what Handler does with it
type countingStack struct {
	Stack
	starts, closes int
}

func (s *countingStack) Start() error { s.starts++; return nil }
func (s *countingStack) Close() error { s.closes++; return nil }

type countingTun struct {
	Tun
	closes int
}

func (t *countingTun) Close() error { t.closes++; return nil }

func TestStartupPolicyIsOptInAndInstanceLocal(t *testing.T) {
	ordinary := context.Background()
	guarded := WithDeferredStartup(WithIPv6Refusal(ordinary))
	if ordinary.Value(ipv6RefusalKey{}) != nil || ordinary.Value(deferredStartupKey{}) != nil {
		t.Fatal("ordinary instances inherited Rantau policy")
	}
	// what Init reads
	if guarded.Value(ipv6RefusalKey{}) != true || guarded.Value(deferredStartupKey{}) != true {
		t.Fatal("instance policy missing")
	}
}

// Packets that the system queued before the core started wait until Activate, which reads them once
func TestDeferredStackReadsOnlyAfterActivation(t *testing.T) {
	p, l := newPeer(t, "172.19.0.2:40100", "198.51.100.10:443")
	s, err := NewStack(context.Background(), StackOptions{Tun: l, MTU: testMTU}, connectionFunc(func(net.Conn, net.Destination) {}))
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{deferred: true, stack: s, tun: l}
	defer h.Close()
	l.in <- ping(p.src.Addr(), p.dst.Addr())
	p.silent(100 * time.Millisecond)
	if err := h.Activate(); err != nil {
		t.Fatal(err)
	}
	if packet, ok := parsePacket(p.packet(), 0); !ok || packet.proto != protoICMPv4 || packet.src != p.dst.Addr() || packet.payload[0] != 0 {
		t.Fatal("queued ping not answered after activation")
	}
	if err := h.Activate(); err != nil {
		t.Fatal("repeated activation: ", err)
	}
	l.in <- ping(p.src.Addr(), netip.MustParseAddr("198.51.100.11"))
	p.packet()
	p.silent(100 * time.Millisecond)
}

func TestActivationStartsOnceAndCloseIsIdempotent(t *testing.T) {
	stack, device := &countingStack{}, &countingTun{}
	h := &Handler{deferred: true, stack: stack, tun: device}
	for i := 0; i < 3; i++ {
		if err := h.Activate(); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil {
		t.Fatal("second close: ", err)
	}
	if err := h.Activate(); err == nil {
		t.Fatal("closed TUN activated")
	}
	if stack.starts != 1 || stack.closes != 1 || device.closes != 1 {
		t.Fatalf("starts=%d closes=%d device closes=%d", stack.starts, stack.closes, device.closes)
	}
}

func TestClosedBeforeActivationNeverStartsReads(t *testing.T) {
	stack := &countingStack{}
	h := &Handler{deferred: true, stack: stack, tun: &countingTun{}}
	h.Close()
	if err := h.Activate(); err == nil || stack.starts != 0 {
		t.Fatal("closed pending TUN started reading")
	}
	if err := (&Handler{deferred: true}).Activate(); err == nil {
		t.Fatal("activated a TUN that never started")
	}
	// started at once without WithDeferredStartup, so Activate has nothing to do
	immediate := &countingStack{}
	if err := (&Handler{stack: immediate}).Activate(); err != nil || immediate.starts != 0 {
		t.Fatal("activation of an ordinary instance started its stack again")
	}
}
