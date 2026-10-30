package tun

import (
	"context"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type startupDispatcher struct{ stack.NetworkDispatcher }
type startupEndpoint struct {
	stack.LinkEndpoint
	calls    []stack.NetworkDispatcher
	closes   int
	onAttach func()
}

func (e *startupEndpoint) Attach(d stack.NetworkDispatcher) {
	e.calls = append(e.calls, d)
	if d != nil && e.onAttach != nil {
		e.onAttach()
	}
}
func (e *startupEndpoint) Close()                           { e.closes++ }
func (e *startupEndpoint) GSOMaxSize() uint32               { return 12345 }
func (e *startupEndpoint) SupportedGSO() stack.SupportedGSO { return stack.HostGSOSupported }

func TestEndpointActivationPublishesInitialization(t *testing.T) {
	initialized := 0
	seen := make(chan int, 1)
	underlying := &startupEndpoint{onAttach: func() { go func() { seen <- initialized }() }}
	endpoint := &deferredLinkEndpoint{LinkEndpoint: underlying}
	dispatcher := &startupDispatcher{}
	endpoint.Attach(dispatcher)
	if len(underlying.calls) != 0 || !endpoint.IsAttached() {
		t.Fatal("attachment started reads before activation")
	}
	initialized = 42
	if err := endpoint.activate(); err != nil {
		t.Fatal(err)
	}
	if got := <-seen; got != 42 {
		t.Fatalf("receiver saw partially initialized state %d", got)
	}
	if err := endpoint.activate(); err != nil {
		t.Fatal(err)
	}
	if len(underlying.calls) != 1 || underlying.calls[0] != dispatcher {
		t.Fatal("activation must attach exactly once")
	}
	if endpoint.GSOMaxSize() != 12345 || endpoint.SupportedGSO() != stack.HostGSOSupported {
		t.Fatal("optional GSO capabilities lost")
	}
	endpoint.Attach(nil)
	if endpoint.IsAttached() || len(underlying.calls) != 2 || underlying.calls[1] != nil {
		t.Fatal("detach not forwarded")
	}
	endpoint.Close()
}

func TestEndpointClosedBeforeActivationNeverStartsReads(t *testing.T) {
	underlying := &startupEndpoint{}
	endpoint := &deferredLinkEndpoint{LinkEndpoint: underlying}
	endpoint.Attach(&startupDispatcher{})
	endpoint.Close()
	endpoint.Close()
	if err := endpoint.activate(); err == nil {
		t.Fatal("closed endpoint reactivated")
	}
	endpoint.Attach(&startupDispatcher{})
	if len(underlying.calls) != 0 || underlying.closes != 1 || endpoint.IsAttached() {
		t.Fatal("closed pending endpoint leaked a reader or closed twice")
	}
}

func TestEndpointDetachedBeforeActivationDoesNotStartReader(t *testing.T) {
	underlying := &startupEndpoint{}
	endpoint := &deferredLinkEndpoint{LinkEndpoint: underlying}
	endpoint.Attach(&startupDispatcher{})
	endpoint.Attach(nil)
	if err := endpoint.activate(); err != nil {
		t.Fatal(err)
	}
	if len(underlying.calls) != 0 {
		t.Fatal("detached dispatcher started reader")
	}
	endpoint.Close()
}

func TestStartupPolicyIsOptInAndInstanceLocal(t *testing.T) {
	ordinary := context.Background()
	guarded := WithDeferredStartup(WithIPv6Refusal(ordinary))
	if ordinary.Value(ipv6RefusalKey{}) != nil || ordinary.Value(deferredStartupKey{}) != nil {
		t.Fatal("ordinary instances inherited Rantau policy")
	}
	if guarded.Value(ipv6RefusalKey{}) != true || guarded.Value(deferredStartupKey{}) == nil {
		t.Fatal("instance policy missing")
	}
	endpoint := &deferredLinkEndpoint{LinkEndpoint: &LinkEndpoint{}}
	if endpoint.GSOMaxSize() != 0 || endpoint.SupportedGSO() != stack.GSONotSupported {
		t.Fatal("non-GSO endpoint gained GSO capability")
	}
}

func TestClosedStackCannotActivateDeferredEndpoint(t *testing.T) {
	underlying := &startupEndpoint{}
	endpoint := &deferredLinkEndpoint{LinkEndpoint: underlying}
	endpoint.Attach(&startupDispatcher{})
	tunStack := &stackGVisor{stack: stack.New(stack.Options{}), endpoint: endpoint}
	if err := tunStack.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tunStack.Activate(); err == nil {
		t.Fatal("closed stack activated its deferred reader")
	}
	if len(underlying.calls) != 0 || underlying.closes != 1 {
		t.Fatal("closed stack leaked a reader or device")
	}
}

func TestDeferredStartupCleanupIsIdempotent(t *testing.T) {
	ctx := WithDeferredStartup(context.Background())
	state := ctx.Value(deferredStartupKey{}).(*deferredStartupState)
	calls := 0
	state.add(func() { calls++ })
	if !CleanupDeferredStartup(ctx) || !CleanupDeferredStartup(ctx) || calls != 1 {
		t.Fatal("resource cleanup or ownership was repeated/lost")
	}
	if CleanupDeferredStartup(context.Background()) {
		t.Fatal("ordinary instance claimed device ownership")
	}
}
