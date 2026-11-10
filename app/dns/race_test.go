package dns

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	feature_dns "github.com/xtls/xray-core/features/dns"
)

// raceServer answers after a wait, or never (until the lookup's own timeout) when stuck.
type raceServer struct {
	name  string
	wait  time.Duration
	stuck bool
	ips   []net.IP
	err   error
	asked atomic.Int32
}

func (s *raceServer) Name() string         { return s.name }
func (s *raceServer) IsDisableCache() bool { return false }
func (s *raceServer) QueryIP(ctx context.Context, _ string, _ feature_dns.IPOption) ([]net.IP, uint32, error) {
	s.asked.Add(1)
	wait := s.wait
	if s.stuck {
		wait = time.Hour
	}
	select {
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	case <-time.After(wait):
	}
	return s.ips, 60, s.err
}

func raceClient(server *raceServer, policy uint32) *Client {
	return &Client{server: server, timeoutMs: 400 * time.Millisecond, policyID: policy, ipOption: &feature_dns.IPOption{IPv4Enable: true}}
}

func raceDNS(clients ...*Client) *DNS {
	return &DNS{ctx: context.Background(), clients: clients, enableParallelQuery: true, ipOption: &feature_dns.IPOption{IPv4Enable: true}, hosts: &StaticHosts{}}
}

var (
	raceOption = feature_dns.IPOption{IPv4Enable: true}
	raceA      = []net.IP{{1, 2, 3, 4}}
	raceB      = []net.IP{{5, 6, 7, 8}}
)

// Two connections to one resolver: the one that answers is used, and a stuck one costs nothing.
func TestRaceTakesTheServerThatAnswers(t *testing.T) {
	stuck := &raceServer{name: "stuck", stuck: true}
	quick := &raceServer{name: "quick", wait: 10 * time.Millisecond, ips: raceA}
	behind := &raceServer{name: "behind", ips: raceB}
	server := raceDNS(raceClient(stuck, 1), raceClient(quick, 1), raceClient(behind, 2))

	start := time.Now()
	ips, _, err := server.parallelQuery("a.example", raceOption)
	if err != nil || len(ips) != 1 || !ips[0].Equal(raceA[0]) {
		t.Fatalf("got %v, %v", ips, err)
	}
	if took := time.Since(start); took > 200*time.Millisecond {
		t.Errorf("took %v: waited for the stuck server", took)
	}
	if behind.asked.Load() != 0 {
		t.Error("the next group was asked although the first had addresses")
	}
}

// One DNS answer without usable addresses decides for its group: the stuck twin is not waited for.
func TestRaceAnswerWithoutAddressesDecidesTheGroup(t *testing.T) {
	for name, miss := range map[string]error{"empty": feature_dns.ErrEmptyResponse, "no such name": feature_dns.RCodeError(3), "nil": nil} {
		t.Run(name, func(t *testing.T) {
			stuck := &raceServer{name: "stuck", stuck: true}
			answers := &raceServer{name: "answers", wait: 10 * time.Millisecond, err: miss}
			behind := &raceServer{name: "behind", ips: raceB}
			server := raceDNS(raceClient(stuck, 1), raceClient(answers, 1), raceClient(behind, 2))

			start := time.Now()
			ips, _, err := server.parallelQuery("a.example", raceOption)
			if err != nil || len(ips) != 1 || !ips[0].Equal(raceB[0]) {
				t.Fatalf("got %v, %v", ips, err)
			}
			if took := time.Since(start); took > 200*time.Millisecond {
				t.Errorf("took %v: waited for the stuck server", took)
			}
		})
	}
}

// A server that fails without a DNS answer (a timeout, a dead connection) does not decide: its twin does.
func TestRaceWaitsForTheTwinOfAFailedServer(t *testing.T) {
	dead := &raceServer{name: "dead", err: errors.New("dial failed")}
	slow := &raceServer{name: "slow", wait: 60 * time.Millisecond, ips: raceA}
	behind := &raceServer{name: "behind", ips: raceB}
	server := raceDNS(raceClient(dead, 1), raceClient(slow, 1), raceClient(behind, 2))

	ips, _, err := server.parallelQuery("a.example", raceOption)
	if err != nil || len(ips) != 1 || !ips[0].Equal(raceA[0]) {
		t.Fatalf("got %v, %v", ips, err)
	}
	if behind.asked.Load() != 0 {
		t.Error("the next group was asked while a server of the first could still answer")
	}
}

// Groups go in order, and a later group is asked only after the one before it has failed.
func TestRaceAsksLaterGroupsOnlyAfterFailure(t *testing.T) {
	first := &raceServer{name: "first", wait: 30 * time.Millisecond, err: feature_dns.RCodeError(3)}
	second := &raceServer{name: "second", err: feature_dns.RCodeError(3)}
	third := &raceServer{name: "third", ips: raceB}
	server := raceDNS(raceClient(first, 1), raceClient(second, 2), raceClient(third, 3))

	done := make(chan struct{})
	go func() {
		defer close(done)
		ips, _, err := server.parallelQuery("a.example", raceOption)
		if err != nil || len(ips) != 1 || !ips[0].Equal(raceB[0]) {
			t.Errorf("got %v, %v", ips, err)
		}
	}()
	time.Sleep(10 * time.Millisecond)
	if second.asked.Load() != 0 || third.asked.Load() != 0 {
		t.Error("later groups were asked before the first had failed")
	}
	<-done
	if first.asked.Load() != 1 || second.asked.Load() != 1 || third.asked.Load() != 1 {
		t.Errorf("asked %d, %d, %d times, want once each", first.asked.Load(), second.asked.Load(), third.asked.Load())
	}
}

// When every group fails, the last server that answered decides the code, as in serial order.
func TestRaceAllFailedKeepsTheLastAnswer(t *testing.T) {
	aside := &raceServer{name: "aside", err: feature_dns.ErrEmptyResponse}
	stuck := &raceServer{name: "stuck", stuck: true}
	gone := &raceServer{name: "gone", err: feature_dns.RCodeError(3)}
	server := raceDNS(raceClient(aside, 1), raceClient(stuck, 1), raceClient(gone, 2))

	_, _, err := server.parallelQuery("a.example", raceOption)
	if got := feature_dns.RCodeFromError(err); got != 3 {
		t.Fatalf("rcode %d, want 3 (%v)", got, err)
	}
}
