package dispatcher

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/core"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/pipe"
)

// sniffed runs the dispatcher's sniffer on a connection whose first payload is given, and times it.
func sniffed(t *testing.T, payload []byte, network xnet.Network, only []string) (SniffResult, error, time.Duration) {
	t.Helper()
	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	defer writer.Close()
	if len(payload) > 0 {
		b := buf.New()
		b.Write(payload)
		if err := writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			t.Fatal(err)
		}
	}
	// the sniffer looks for the instance's FakeDNS: an instance without one
	instance, err := core.New(&core.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), core.XrayKey(1), instance)
	start := time.Now()
	result, err := sniffer(ctx, &cachedReader{reader: reader}, false, network, only)
	return result, err, time.Since(start)
}

var asked = []string{"http", "tls", "quic"}

// A first datagram or payload under 20 bytes waited for more data, because the BitTorrent sniffers could not
// tell yet. An instance that asks only for the protocols it routes by decides at once.
func TestOverrideSniffersOnlyDoesNotWaitOnShortPayloads(t *testing.T) {
	short := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	for name, network := range map[string]xnet.Network{"udp": xnet.Network_UDP, "tcp": xnet.Network_TCP} {
		t.Run(name, func(t *testing.T) {
			if _, err, took := sniffed(t, short, network, nil); err == nil || took < 150*time.Millisecond {
				t.Fatalf("all sniffers: %v after %v, expected Xray's wait for more data", err, took)
			}
			if _, err, took := sniffed(t, short, network, asked); err == nil || took > 50*time.Millisecond {
				t.Fatalf("asked sniffers only: %v after %v, want no wait", err, took)
			}
		})
	}
}

// The protocols that are asked for are still read.
func TestOverrideSniffersOnlyStillReadsNames(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		_ = tls.Client(client, &tls.Config{ServerName: "www.example.com"}).Handshake()
	}()
	hello := make([]byte, 4096)
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := server.Read(hello)
	if err != nil {
		t.Fatal(err)
	}
	_ = server.Close()
	_ = client.Close()

	result, err, _ := sniffed(t, hello[:n], xnet.Network_TCP, asked)
	if err != nil || result.Protocol() != "tls" || result.Domain() != "www.example.com" {
		t.Fatalf("TLS: %v, %v", result, err)
	}
	result, err, _ = sniffed(t, []byte("GET / HTTP/1.1\r\nHost: www.example.org\r\n\r\n"), xnet.Network_TCP, asked)
	if err != nil || result.Protocol() != "http1" || result.Domain() != "www.example.org" {
		t.Fatalf("HTTP: %v, %v", result, err)
	}
	// and one that is not asked for is not: no result, at once
	if result, err, took := sniffed(t, []byte("GET / HTTP/1.1\r\nHost: www.example.org\r\n\r\n"), xnet.Network_TCP, []string{"tls"}); err == nil || took > 50*time.Millisecond {
		t.Fatalf("HTTP without being asked: %v after %v", result, took)
	}
}

func TestSnifferOnlyKeepsMetadataSniffers(t *testing.T) {
	s := &Sniffer{sniffer: []protocolSnifferWithMetadata{
		{protocol: "http"}, {protocol: "bittorrent"}, {metadataSniffer: true, protocol: "fakedns"}, {protocol: "quic"},
	}}
	s.Only([]string{"quic", "http"})
	if len(s.sniffer) != 3 || s.sniffer[0].protocol != "http" || !s.sniffer[1].metadataSniffer || s.sniffer[2].protocol != "quic" {
		t.Fatalf("kept %+v", s.sniffer)
	}
}
