package tun

import "context"

type ipv6RefusalKey struct{}
type deferredStartupKey struct{}

// WithDeferredStartup keeps TUN packet reads paused until Handler.Activate is
// called after the core instance and its outbounds have started. The TUN is
// opened, as always, when the inbound starts.
func WithDeferredStartup(ctx context.Context) context.Context {
	return context.WithValue(ctx, deferredStartupKey{}, true)
}

// WithIPv6Refusal asks this TUN instance to refuse IPv6 TCP/UDP before accepting
// traffic. Clients without IPv6 egress can request IPv4 fallback; other users
// retain the normal IPv6 forwarding behavior. The setting is instance-local.
func WithIPv6Refusal(ctx context.Context) context.Context {
	return context.WithValue(ctx, ipv6RefusalKey{}, true)
}
