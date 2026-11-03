//go:build !preconnect_trial

package outbound

import "time"

// Today's reserve (Android 0.1.27 and later): a spare lives two seconds, below even
// the historical four-second server handshake timeout, so it only helps a burst of
// requests and is never checked or replaced. A trial build swaps in
// preconnect_policy_trial.go with -tags preconnect_trial.
const preconnectPolicyName = "standard"

var preconnectBuildPolicy = preconnectPolicy{ttlMin: 2 * time.Second, ttlMax: 2 * time.Second}
