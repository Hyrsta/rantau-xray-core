package reality

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

type closeCounter struct {
	net.Conn
	closes atomic.Int32
}

func (c *closeCounter) Close() error { c.closes.Add(1); return c.Conn.Close() }

// Configuration/handshake failures can return no wrapped connection. Verify
// speculative dials still release the original raw socket and normal dial
// ownership remains unchanged. All operations are local and send no packets.
func TestReserveFailureClosesRawSocketOnlyForReserve(t *testing.T) {
	for _, reserve := range []bool{false, true} {
		left, right := net.Pipe()
		c := &closeCounter{Conn: left}
		ctx := context.Background()
		if reserve {
			ctx = session.ContextWithPreconnect(ctx)
		}
		conn, err := UClient(c, &Config{Fingerprint: "invalid-fingerprint"}, ctx, xnet.TCPDestination(xnet.LocalHostIP, 443))
		if conn != nil || err == nil {
			t.Fatal("invalid fingerprint accepted")
		}
		if (c.closes.Load() > 0) != reserve {
			t.Fatalf("reserve=%v raw closes=%d", reserve, c.closes.Load())
		}
		left.Close()
		right.Close()
	}
}
