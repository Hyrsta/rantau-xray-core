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
// No caller releases transferred buffers; both delivered and discarded packets
// must return their storage to the pool after payload/metadata use is finished.
func TestUDPWriterReleasesDeliveredSkippedAndFailedBuffers(t *testing.T) {
	client := net.UDPDestination(net.ParseAddress("172.19.0.2"), 41004)
	remote := net.UDPDestination(net.ParseAddress("198.51.100.1"), 3478)
	alternate := net.UDPDestination(net.ParseAddress("198.51.100.2"), 50000)
	incompatible := net.UDPDestination(net.ParseAddress("2001:db8::1"), 3478)
	tests := []struct {
		payload string
		from    *net.Destination
	}{
		{"default", nil},
		{"alternate", &alternate},
		{"skipped family", &incompatible},
		{"failed write", &alternate},
		{"after failure", nil},
	}
	mb := make(buf.MultiBuffer, len(tests))
	for i, test := range tests {
		mb[i] = buf.New()
		mb[i].Write([]byte(test.payload))
		mb[i].UDP = test.from
	}
	// Keep object references separately: ReleaseMulti must clear the input slice.
	objects := append(buf.MultiBuffer(nil), mb...)
	t.Cleanup(func() { buf.ReleaseMulti(objects) }) // also cleans a failing regression
	writes := 0
	wantIndices := []int{0, 1, 3, 4}
	h := newUdpConnectionHandler(nil, func(p []byte, from, to net.Destination) error {
		if writes >= len(wantIndices) {
			t.Fatal("incompatible-family buffer was written")
		}
		i := wantIndices[writes]
		want := tests[i]
		wantSource := remote
		if want.from != nil {
			wantSource = *want.from
		}
		if string(p) != want.payload || from != wantSource || to != client {
			t.Fatalf("incorrect packet before release: %q %v -> %v", p, from, to)
		}
		if string(objects[i].Bytes()) != want.payload || objects[i].UDP != want.from {
			t.Fatal("payload or UDP metadata released before writePacket returned")
		}
		writes++
		if want.payload == "failed write" {
			return errors.New("synthetic packet write failure")
		}
		return nil
	})
	conn := &udpConn{handler: h, src: client, dst: remote}
	if err := buf.Copy(&udpOwnedBufferReader{mb: mb}, buf.NewWriter(conn)); err != nil {
		t.Fatal(err)
	}
	if writes != len(wantIndices) {
		t.Fatalf("got %d packet writes, want %d", writes, len(wantIndices))
	}
	for i, b := range objects {
		if mb[i] != nil || b.Len() != 0 || b.Bytes() != nil || b.UDP != nil {
			t.Fatalf("buffer %d was not released after write/discard", i)
		}
	}
}
