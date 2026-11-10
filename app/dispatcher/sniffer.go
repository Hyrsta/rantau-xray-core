package dispatcher

import (
	"context"
	"slices"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/bittorrent"
	"github.com/xtls/xray-core/common/protocol/http"
	"github.com/xtls/xray-core/common/protocol/quic"
	"github.com/xtls/xray-core/common/protocol/tls"
)

type SniffResult interface {
	Protocol() string
	Domain() string
}

type protocolSniffer func(context.Context, []byte) (SniffResult, error)

type protocolSnifferWithMetadata struct {
	protocolSniffer protocolSniffer
	// A Metadata sniffer will be invoked on connection establishment only, with nil body,
	// for both TCP and UDP connections
	// It will not be shown as a traffic type for routing unless there is no other successful sniffing.
	metadataSniffer bool
	network         net.Network
	// protocol is what a content sniffer finds, as inbounds name it in destOverride
	protocol string
}

type Sniffer struct {
	sniffer []protocolSnifferWithMetadata
}

func NewSniffer(ctx context.Context) *Sniffer {
	ret := &Sniffer{
		sniffer: []protocolSnifferWithMetadata{
			{func(c context.Context, b []byte) (SniffResult, error) { return http.SniffHTTP(b, c) }, false, net.Network_TCP, "http"},
			{func(c context.Context, b []byte) (SniffResult, error) { return tls.SniffTLS(b) }, false, net.Network_TCP, "tls"},
			{func(c context.Context, b []byte) (SniffResult, error) { return bittorrent.SniffBittorrent(b) }, false, net.Network_TCP, "bittorrent"},
			{func(c context.Context, b []byte) (SniffResult, error) { return quic.SniffQUIC(b) }, false, net.Network_UDP, "quic"},
			{func(c context.Context, b []byte) (SniffResult, error) { return bittorrent.SniffUTP(b) }, false, net.Network_UDP, "bittorrent"},
		},
	}
	if sniffer, err := newFakeDNSSniffer(ctx); err == nil {
		others := ret.sniffer
		ret.sniffer = append(ret.sniffer, sniffer)
		fakeDNSThenOthers, err := newFakeDNSThenOthers(ctx, sniffer, others)
		if err == nil {
			ret.sniffer = append([]protocolSnifferWithMetadata{fakeDNSThenOthers}, ret.sniffer...)
		}
	}
	return ret
}

// overrideSniffersKey marks an instance whose dispatcher runs only the content sniffers an inbound names in
// destOverride, see WithOverrideSniffersOnly.
type overrideSniffersKey struct{}

// WithOverrideSniffersOnly asks this instance's dispatcher to run, for each connection, only the content
// sniffers of the protocols its inbound names in destOverride. Xray runs all of them, so that routing rules
// can name a protocol, and each one that cannot tell yet makes the connection wait for more data: BitTorrent's
// need 20 bytes, so a first UDP datagram or TCP payload shorter than that (a game's ping, a small request)
// waited for a second one, up to 200 ms. An instance that routes by name only loses nothing but that wait.
// Metadata sniffers (FakeDNS) are kept. The setting is instance-local.
func WithOverrideSniffersOnly(ctx context.Context) context.Context {
	return context.WithValue(ctx, overrideSniffersKey{}, true)
}

// Only leaves the content sniffers of the named protocols, and every metadata sniffer.
func (s *Sniffer) Only(protocols []string) {
	kept := make([]protocolSnifferWithMetadata, 0, len(s.sniffer))
	for _, si := range s.sniffer {
		if si.metadataSniffer || slices.Contains(protocols, si.protocol) {
			kept = append(kept, si)
		}
	}
	s.sniffer = kept
}

var errUnknownContent = errors.New("unknown content")

func (s *Sniffer) Sniff(c context.Context, payload []byte, network net.Network) (SniffResult, error) {
	var pendingSniffer []protocolSnifferWithMetadata
	for _, si := range s.sniffer {
		protocolSniffer := si.protocolSniffer
		if si.metadataSniffer || si.network != network {
			continue
		}
		result, err := protocolSniffer(c, payload)
		if err == common.ErrNoClue {
			pendingSniffer = append(pendingSniffer, si)
			continue
		} else if err == protocol.ErrProtoNeedMoreData { // Sniffer protocol matched, but need more data to complete sniffing
			s.sniffer = []protocolSnifferWithMetadata{si}
			return nil, err
		}

		if err == nil && result != nil {
			return result, nil
		}
	}

	if len(pendingSniffer) > 0 {
		s.sniffer = pendingSniffer
		return nil, common.ErrNoClue
	}

	return nil, errUnknownContent
}

func (s *Sniffer) SniffMetadata(c context.Context) (SniffResult, error) {
	var pendingSniffer []protocolSnifferWithMetadata
	for _, si := range s.sniffer {
		s := si.protocolSniffer
		if !si.metadataSniffer {
			pendingSniffer = append(pendingSniffer, si)
			continue
		}
		result, err := s(c, nil)
		if err == common.ErrNoClue {
			pendingSniffer = append(pendingSniffer, si)
			continue
		}

		if err == nil && result != nil {
			return result, nil
		}
	}

	if len(pendingSniffer) > 0 {
		s.sniffer = pendingSniffer
		return nil, common.ErrNoClue
	}

	return nil, errUnknownContent
}

func CompositeResult(domainResult SniffResult, protocolResult SniffResult) SniffResult {
	return &compositeResult{domainResult: domainResult, protocolResult: protocolResult}
}

type compositeResult struct {
	domainResult   SniffResult
	protocolResult SniffResult
}

func (c compositeResult) Protocol() string {
	return c.protocolResult.Protocol()
}

func (c compositeResult) Domain() string {
	return c.domainResult.Domain()
}

func (c compositeResult) ProtocolForDomainResult() string {
	return c.domainResult.Protocol()
}

type SnifferResultComposite interface {
	ProtocolForDomainResult() string
}

type SnifferIsProtoSubsetOf interface {
	IsProtoSubsetOf(protocolName string) bool
}
