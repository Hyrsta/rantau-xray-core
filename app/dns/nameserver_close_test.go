package dns

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// linkDispatcher hands the test the far end of every link the nameserver opens
type linkDispatcher struct{ far chan *transport.Link }

func (d *linkDispatcher) Type() interface{} { return routing.DispatcherType() }
func (d *linkDispatcher) Start() error      { return nil }
func (d *linkDispatcher) Close() error      { return nil }
func (d *linkDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	upReader, upWriter := pipe.New()
	downReader, downWriter := pipe.New()
	d.far <- &transport.Link{Reader: upReader, Writer: downWriter}
	return &transport.Link{Reader: downReader, Writer: upWriter}, nil
}
func (d *linkDispatcher) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	return nil
}

// Closing the DNS app ends a UDP nameserver's link at once. Left to its idle timer, the link (and the outbound
// behind it) kept the dispatcher and the whole closed instance for one to two minutes after every restart.
func TestCloseEndsUDPNameServerLink(t *testing.T) {
	d := &linkDispatcher{far: make(chan *transport.Link, 1)}
	server := NewClassicNameServer(net.UDPDestination(net.IPAddress([]byte{1, 1, 1, 1}), 53), d, true, false, 0, nil)
	app := &DNS{clients: []*Client{{server: server}}}
	instance, err := core.New(&core.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), core.XrayKey(1), instance), 2*time.Second)
	defer cancel()
	go server.QueryIP(ctx, "example.com", dns.IPOption{IPv4Enable: true})
	var far *transport.Link
	select {
	case far = <-d.far:
	case <-time.After(2 * time.Second):
		t.Fatal("the query opened no link")
	}
	if _, err := far.Reader.ReadMultiBuffer(); err != nil {
		t.Fatal("no query on the link: ", err)
	}

	ended := make(chan error, 1)
	go func() {
		for {
			if _, err := far.Reader.ReadMultiBuffer(); err != nil {
				ended <- err
				return
			}
		}
	}()
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ended:
	case <-time.After(time.Second):
		t.Fatal("the nameserver's link outlived the closed DNS app")
	}
}
