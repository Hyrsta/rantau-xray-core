package dns

import (
	go_errors "errors"
	"testing"

	"github.com/xtls/xray-core/common/errors"
	feature_dns "github.com/xtls/xray-core/features/dns"
)

// When the servers disagree, the last one that answered decides, so the DNS outbound can still answer the client.
// Before, any disagreement gave a combined error with no DNS code, and the client got no answer at all.
func TestMergeQueryErrorsKeepsAnAnswer(t *testing.T) {
	empty := feature_dns.ErrEmptyResponse
	nxdomain, servfail := feature_dns.RCodeError(3), feature_dns.RCodeError(2)
	other := errors.New("dial failed")
	for _, tc := range []struct {
		name      string
		errs      []error
		rcode     uint16
		wantEmpty bool
	}{
		{"set aside, then no such name", []error{empty, nxdomain, nxdomain}, 3, false},
		{"set aside, no such name, no response", []error{empty, nxdomain, errRecordNotFound}, 3, false},
		{"server failure, then no such name", []error{servfail, nxdomain}, 3, false},
		{"set aside, then server failure", []error{empty, servfail}, 2, false},
		{"no such name, then no address", []error{nxdomain, empty}, 0, true},
		// As before.
		{"all no such name", []error{nxdomain, nxdomain}, 3, false},
		{"no response, then no such name", []error{errRecordNotFound, nxdomain}, 3, false},
		{"set aside, then no response", []error{empty, errRecordNotFound}, 0, true},
		{"none", nil, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := mergeQueryErrors("a.example", tc.errs)
			if got := feature_dns.RCodeFromError(err); got != tc.rcode {
				t.Errorf("rcode %d, want %d (%v)", got, tc.rcode, err)
			}
			if got := go_errors.Is(err, empty); got != tc.wantEmpty {
				t.Errorf("empty %v, want %v (%v)", got, tc.wantEmpty, err)
			}
		})
	}
	// Nothing to answer with: no response at all, or the last server failed without a DNS answer.
	for _, errs := range [][]error{{errRecordNotFound}, {empty, other}, {nxdomain, other}} {
		err := mergeQueryErrors("a.example", errs)
		if feature_dns.RCodeFromError(err) != 0 || go_errors.Is(err, empty) {
			t.Errorf("%v: got an answer, %v", errs, err)
		}
	}
}
