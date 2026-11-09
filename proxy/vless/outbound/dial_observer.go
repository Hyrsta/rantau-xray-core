package outbound

import (
	"context"
	"sync/atomic"

	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// The Rantau engine watches whether this outbound can still reach its server, so a tunnel
// whose new connections fail is checked at once instead of at its next periodic check.
var dialObserver atomic.Pointer[func(context.Context, error)]

// SetDialObserver sets one process-wide function told the outcome of each dial to a VLESS
// server (TCP connect and TLS/REALITY handshake): every attempt of a request, a health
// check's (session.IsPreconnectDisabled) and a reserve's (session.IsPreconnect). err is nil
// for a connection. What the server later says about the request's own destination is not
// a dial. nil removes the function. It must return quickly.
func SetDialObserver(observe func(ctx context.Context, err error)) {
	if observe == nil {
		dialObserver.Store(nil)
		return
	}
	dialObserver.Store(&observe)
}

func (h *Handler) dialServer(ctx context.Context, dialer internet.Dialer) (stat.Connection, error) {
	conn, err := dialer.Dial(ctx, h.server.Destination)
	if observe := dialObserver.Load(); observe != nil {
		(*observe)(ctx, err)
	}
	return conn, err
}
