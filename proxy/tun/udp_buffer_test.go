package tun

import (
	"errors"
	"io"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

type udpOwnedBufferReader struct{ mb buf.MultiBuffer }

func (r *udpOwnedBufferReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb := r.mb
	r.mb = nil
	return mb, io.EOF
}

// Exercise the caller's actual buf.Copy -> buf.NewWriter(conn) ownership path.
// No caller releases transferred buffers: written, redirected and unwritten
// packets must all return their storage to the pool after the payload and its
// metadata are used, also when a write fails and the rest is not written.
func TestUDPWriterReleasesWrittenAndUnwrittenBuffers(t *testing.T) {
	client := net.UDPDestination(net.ParseAddress("172.19.0.2"), 41004)
	remote := net.UDPDestination(net.ParseAddress("198.51.100.1"), 3478)
	alternate := net.UDPDestination(net.ParseAddress("198.51.100.2"), 50000)
	domain := net.UDPDestination(net.DomainAddress("example.com"), 3478)
	tests := []struct {
		payload string
		from    *net.Destination
		// to is where the packet is written from, nil if it is not written
		to *net.Destination
	}{
		{"default", nil, &remote},
		{"alternate", &alternate, &alternate},
		{"domain goes back the way it came", &domain, &remote},
		{"failed write", &alternate, &alternate},
		{"after failure", nil, nil},
	}
	mb := make(buf.MultiBuffer, len(tests))
	for i, test := range tests {
		mb[i] = buf.New()
		mb[i].Write([]byte(test.payload))
		mb[i].UDP = test.from
	}
	// Keep object references separately: releasing clears entries of the input slice.
	objects := append(buf.MultiBuffer(nil), mb...)
	t.Cleanup(func() { buf.ReleaseMulti(objects) }) // also cleans a failing regression
	writes := 0
	h := newUdpConnectionHandler(nil, func(p []byte, from, to net.Destination) error {
		if writes >= len(tests) || tests[writes].to == nil {
			t.Fatal("a packet after the failed one was written")
		}
		want := tests[writes]
		if string(p) != want.payload || from != *want.to || to != client {
			t.Fatalf("incorrect packet before release: %q %v -> %v", p, from, to)
		}
		if string(objects[writes].Bytes()) != want.payload || objects[writes].UDP != want.from {
			t.Fatal("payload or UDP metadata released before writePacket returned")
		}
		writes++
		if want.payload == "failed write" {
			return errors.New("synthetic packet write failure")
		}
		return nil
	})
	conn := &udpConn{handler: h, src: client, dst: remote}
	if err := buf.Copy(&udpOwnedBufferReader{mb: mb}, buf.NewWriter(conn)); err == nil {
		t.Fatal("the failed write was not reported")
	}
	if writes != 4 {
		t.Fatalf("got %d packet writes, want 4", writes)
	}
	for i, b := range objects {
		if b.Len() != 0 || b.Bytes() != nil || b.UDP != nil {
			t.Fatalf("buffer %d was not released after write/discard", i)
		}
	}
}
