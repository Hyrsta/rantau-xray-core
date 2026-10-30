package tun

import (
	"context"
	"errors"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type ipv6RefusalKey struct{}
type deferredStartupKey struct{}

// WithDeferredStartup keeps TUN packet reads paused until Handler.Activate is
// called after the core instance and its outbounds have started.
func WithDeferredStartup(ctx context.Context) context.Context {
	return WithDeferredStartupCleanup(ctx, nil)
}

// WithDeferredStartupCleanup also supplies device cleanup for embedders that own
// a duplicated VPN descriptor. Registration happens immediately after NewTun,
// so even a partially failed inbound constructor uses the same ownership rule.
func WithDeferredStartupCleanup(ctx context.Context, cleanup func(Tun)) context.Context {
	return context.WithValue(ctx, deferredStartupKey{}, &deferredStartupState{cleanup: cleanup})
}

type deferredStartupState struct {
	mu              sync.Mutex
	cleanup         func(Tun)
	resources       []func()
	closed, handled bool
}

func (s *deferredStartupState) add(cleanup func()) {
	s.mu.Lock()
	s.handled = true
	if !s.closed {
		s.resources = append(s.resources, cleanup)
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	cleanup()
}

// CleanupDeferredStartup releases resources when core.New fails without
// returning an instance. True means an initialized device was handled; repeated
// calls remain true and cannot close a reused descriptor.
func CleanupDeferredStartup(ctx context.Context) bool {
	s, _ := ctx.Value(deferredStartupKey{}).(*deferredStartupState)
	if s == nil {
		return false
	}
	s.mu.Lock()
	s.closed = true
	resources := s.resources
	s.resources = nil
	handled := s.handled
	s.mu.Unlock()
	for _, cleanup := range resources {
		cleanup()
	}
	return handled
}

// WithIPv6Refusal asks this TUN instance to refuse IPv6 TCP/UDP before accepting
// traffic. Clients without IPv6 egress can request IPv4 fallback; other users
// retain the normal IPv6 forwarding behavior. The setting is instance-local.
func WithIPv6Refusal(ctx context.Context) context.Context {
	return context.WithValue(ctx, ipv6RefusalKey{}, true)
}

// CreateNIC attaches its endpoint immediately, before the stack's transport
// handlers and route configuration are ready. Defer that attachment until the
// owner explicitly activates it. Activation publishes all initialization before
// the underlying endpoint starts its receive goroutines, including fdbased.
type deferredLinkEndpoint struct {
	stack.LinkEndpoint
	mu             sync.Mutex
	dispatcher     stack.NetworkDispatcher
	active, closed bool
}

func (e *deferredLinkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	e.dispatcher = dispatcher
	if e.active {
		e.LinkEndpoint.Attach(dispatcher)
	}
}

func (e *deferredLinkEndpoint) IsAttached() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return !e.closed && e.dispatcher != nil
}

func (e *deferredLinkEndpoint) activate() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return errors.New("TUN endpoint closed before activation")
	}
	if !e.active {
		e.active = true
		if e.dispatcher != nil {
			e.LinkEndpoint.Attach(e.dispatcher)
		}
	}
	return nil
}

func (e *deferredLinkEndpoint) Close() {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.closed = true
	e.dispatcher = nil
	if e.active {
		e.LinkEndpoint.Attach(nil)
	}
	e.mu.Unlock()
	e.LinkEndpoint.Close()
}

// Embedding LinkEndpoint forwards all required capabilities. GSO is an optional
// interface, so forward it explicitly rather than silently disabling it.
func (e *deferredLinkEndpoint) GSOMaxSize() uint32 {
	if gso, ok := e.LinkEndpoint.(stack.GSOEndpoint); ok {
		return gso.GSOMaxSize()
	}
	return 0
}
func (e *deferredLinkEndpoint) SupportedGSO() stack.SupportedGSO {
	if gso, ok := e.LinkEndpoint.(stack.GSOEndpoint); ok {
		return gso.SupportedGSO()
	}
	return stack.GSONotSupported
}
