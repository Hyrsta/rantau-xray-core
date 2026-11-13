package inbound

import (
	hysteria_proxy "github.com/xtls/xray-core/proxy/hysteria"
)

// Rantau: a Hysteria inbound must still hand its listener the validator of its users (worker.go). The
// check lives in a test so that the package itself does not link Hysteria and QUIC.
var _ listenContexter = (*hysteria_proxy.Server)(nil)
