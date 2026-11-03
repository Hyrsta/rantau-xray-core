package outbound

import "time"

// The reserve's policy (docs/PRECONNECT.md), chosen by the owner after the 2026-11-03
// trial (before it a spare lived two seconds and was never checked). A spare
// waits 20-40 s at random, well inside the servers' 60 s wait for a first request, so
// the first request after a short pause skips the TCP and REALITY handshakes. It is
// checked through TLS just before use, so a spare the server already closed falls back
// to a normal dial instead of failing. warm 0: an expiring spare is not replaced, so a
// device that stops making requests stops making connections.
//
// To trial another policy, put it in a file behind a build tag and give this file the
// opposite tag, as the 2026-11-03 trial did with -tags preconnect_trial.
const preconnectPolicyName = "standard"

var preconnectBuildPolicy = preconnectPolicy{
	ttlMin: 20 * time.Second,
	ttlMax: 40 * time.Second,
	check:  2 * time.Millisecond,
	warm:   0,
}
