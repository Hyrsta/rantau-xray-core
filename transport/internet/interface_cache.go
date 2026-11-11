package internet

import (
	"net"
	"sync"
	"time"
)

// Rantau: a bound dial looked its interface up by name every time (sockopt_windows.go). On Windows that lists every
// adapter of the computer: 53-390 ms on a PC with 14 of them (measured 2026-11-11), paid by each new direct
// connection. The answer is kept instead:
//   - up to interfaceFresh old it is used as it is;
//   - older, it is still used at once and looked up again behind the dial;
//   - older than interfaceStale (no bound dial for that long) it is looked up first, as before;
//   - a lookup that fails, or a socket option that refuses the index (forgetInterface), drops it.
//
// So a changed adapter is noticed within interfaceFresh of use, and no dial waits for the list while dials keep coming.
const (
	interfaceFresh = 10 * time.Second
	interfaceStale = 60 * time.Second
)

type knownInterface struct {
	inf        *net.Interface
	at         time.Time
	refreshing bool
}

var (
	interfaceLock   sync.Mutex
	knownInterfaces = map[string]*knownInterface{}
	// Replaced by tests.
	lookupInterface = net.InterfaceByName
	interfaceNow    = time.Now
)

// interfaceByName is net.InterfaceByName with the answer kept as described above.
func interfaceByName(name string) (*net.Interface, error) {
	now := interfaceNow()
	interfaceLock.Lock()
	if known := knownInterfaces[name]; known != nil {
		age := now.Sub(known.at)
		if age <= interfaceStale {
			if age > interfaceFresh && !known.refreshing {
				known.refreshing = true
				go refreshInterface(name)
			}
			inf := known.inf
			interfaceLock.Unlock()
			return inf, nil
		}
	}
	interfaceLock.Unlock()
	inf, err := lookupInterface(name)
	interfaceLock.Lock()
	defer interfaceLock.Unlock()
	if err != nil {
		delete(knownInterfaces, name)
		return nil, err
	}
	knownInterfaces[name] = &knownInterface{inf: inf, at: interfaceNow()}
	return inf, nil
}

func refreshInterface(name string) {
	inf, err := lookupInterface(name)
	interfaceLock.Lock()
	defer interfaceLock.Unlock()
	if err != nil {
		delete(knownInterfaces, name)
		return
	}
	knownInterfaces[name] = &knownInterface{inf: inf, at: interfaceNow()}
}

// forgetInterface drops what is kept for name: the next bound dial looks it up again.
func forgetInterface(name string) {
	interfaceLock.Lock()
	delete(knownInterfaces, name)
	interfaceLock.Unlock()
}
