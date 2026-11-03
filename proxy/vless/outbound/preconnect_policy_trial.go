//go:build preconnect_trial

package outbound

import "time"

// Trial reserve (docs/PRECONNECT.md), built only with -tags preconnect_trial. A spare
// waits up to 20-40 s, well inside the servers' 60 s, so the first request after a
// short pause skips the TCP and REALITY handshakes. It is checked through TLS just
// before use, so a spare the server already closed falls back to a normal dial
// instead of failing. warm 0: an expiring spare is not replaced, so a device that
// stops making requests stops making connections (owner to confirm these values).
const preconnectPolicyName = "trial"

var preconnectBuildPolicy = preconnectPolicy{
	ttlMin: 20 * time.Second,
	ttlMax: 40 * time.Second,
	check:  2 * time.Millisecond,
	warm:   0,
}
