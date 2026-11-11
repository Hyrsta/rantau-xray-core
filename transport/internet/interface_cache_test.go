package internet

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A stand-in for the system's interface list: counts lookups and answers with the index set now.
type fakeInterfaces struct {
	lookups atomic.Int32
	index   atomic.Int32
	gone    atomic.Bool
	now     atomic.Int64 // seconds
	looked  chan struct{}
}

func useFakeInterfaces(t *testing.T) *fakeInterfaces {
	f := &fakeInterfaces{looked: make(chan struct{}, 16)}
	f.index.Store(7)
	oldLookup, oldNow := lookupInterface, interfaceNow
	interfaceLock.Lock()
	knownInterfaces = map[string]*knownInterface{}
	interfaceLock.Unlock()
	lookupInterface = func(name string) (*net.Interface, error) {
		f.lookups.Add(1)
		defer func() { f.looked <- struct{}{} }()
		if f.gone.Load() {
			return nil, errors.New("no such interface")
		}
		return &net.Interface{Index: int(f.index.Load()), Name: name}, nil
	}
	interfaceNow = func() time.Time { return time.Unix(f.now.Load(), 0) }
	t.Cleanup(func() {
		lookupInterface, interfaceNow = oldLookup, oldNow
		interfaceLock.Lock()
		knownInterfaces = map[string]*knownInterface{}
		interfaceLock.Unlock()
	})
	return f
}

func (f *fakeInterfaces) waitLookup(t *testing.T) {
	t.Helper()
	select {
	case <-f.looked:
	case <-time.After(2 * time.Second):
		t.Fatal("no lookup happened")
	}
}

func TestInterfaceIsLookedUpOnceWhileFresh(t *testing.T) {
	f := useFakeInterfaces(t)
	for i := 0; i < 50; i++ {
		inf, err := interfaceByName("Wi-Fi")
		if err != nil || inf.Index != 7 {
			t.Fatalf("dial %d: %v %v", i, inf, err)
		}
		f.now.Add(0) // the same moment
	}
	if n := f.lookups.Load(); n != 1 {
		t.Fatalf("lookups = %d, want 1", n)
	}
}

func TestOlderAnswerIsUsedAtOnceAndLookedUpBehindTheDial(t *testing.T) {
	f := useFakeInterfaces(t)
	if _, err := interfaceByName("Wi-Fi"); err != nil {
		t.Fatal(err)
	}
	f.waitLookup(t)
	f.index.Store(9) // the adapter was made again with another index
	f.now.Store(int64(interfaceFresh/time.Second) + 1)
	inf, err := interfaceByName("Wi-Fi")
	if err != nil || inf.Index != 7 {
		t.Fatalf("the dial must not wait: got %v %v", inf, err)
	}
	f.waitLookup(t) // the lookup behind it
	deadline := time.Now().Add(2 * time.Second)
	for {
		inf, _ = interfaceByName("Wi-Fi")
		if inf != nil && inf.Index == 9 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the new index never arrived: %v", inf)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if n := f.lookups.Load(); n != 2 {
		t.Fatalf("lookups = %d, want 2", n)
	}
}

func TestOnlyOneLookupRunsBehindManyDials(t *testing.T) {
	f := useFakeInterfaces(t)
	interfaceByName("Wi-Fi")
	f.waitLookup(t)
	f.now.Store(int64(interfaceFresh/time.Second) + 1)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); interfaceByName("Wi-Fi") }()
	}
	wg.Wait()
	f.waitLookup(t)
	time.Sleep(50 * time.Millisecond)
	if n := f.lookups.Load(); n != 2 {
		t.Fatalf("lookups = %d, want 2", n)
	}
}

func TestAfterALongPauseTheDialLooksUpFirst(t *testing.T) {
	f := useFakeInterfaces(t)
	interfaceByName("Wi-Fi")
	f.index.Store(9)
	f.now.Store(int64(interfaceStale/time.Second) + 1)
	inf, err := interfaceByName("Wi-Fi")
	if err != nil || inf.Index != 9 {
		t.Fatalf("got %v %v, want the index of now", inf, err)
	}
}

func TestAnInterfaceThatIsGoneIsForgotten(t *testing.T) {
	f := useFakeInterfaces(t)
	interfaceByName("Wi-Fi")
	f.waitLookup(t)
	f.gone.Store(true)
	f.now.Store(int64(interfaceFresh/time.Second) + 1)
	if _, err := interfaceByName("Wi-Fi"); err != nil {
		t.Fatal("the kept answer serves this dial")
	}
	f.waitLookup(t)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := interfaceByName("Wi-Fi"); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a missing interface kept answering")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestForgetMakesTheNextDialLookUp(t *testing.T) {
	f := useFakeInterfaces(t)
	interfaceByName("Wi-Fi")
	f.index.Store(9)
	forgetInterface("Wi-Fi")
	inf, err := interfaceByName("Wi-Fi")
	if err != nil || inf.Index != 9 || f.lookups.Load() != 2 {
		t.Fatalf("got %v %v after %d lookups", inf, err, f.lookups.Load())
	}
}
