//go:build xray_ech_dns

package tls

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common"
)

// Rantau: moved from ech_test.go unchanged; it needs the lookup that only -tags xray_ech_dns builds in.

func TestECHDial(t *testing.T) {
	config := &Config{
		ServerName:    "cloudflare.com",
		EchConfigList: "encryptedsni.com+udp://1.1.1.1",
	}
	// test concurrent Dial(to test cache problem)
	wg := sync.WaitGroup{}
	for range 10 {
		wg.Go(func() {
			TLSConfig := config.GetTLSConfig()
			TLSConfig.NextProtos = []string{"http/1.1"}
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: TLSConfig,
				},
			}
			resp, err := client.Get("https://cloudflare.com/cdn-cgi/trace")
			common.Must(err)
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			common.Must(err)
			if !strings.Contains(string(body), "sni=encrypted") {
				t.Error("ECH Dial success but SNI is not encrypted")
			}
		})
	}
	wg.Wait()
	// check cache
	echConfigCache, ok := GlobalECHConfigCache.Load(ECHCacheKey("udp://1.1.1.1", "encryptedsni.com", nil))
	if !ok {
		t.Error("ECH config cache not found")
	}
	ok = echConfigCache.UpdateLock.TryLock()
	if !ok {
		t.Error("ECH config cache dead lock detected")
	}
	echConfigCache.UpdateLock.Unlock()
	configRecord := echConfigCache.configRecord.Load()
	if configRecord == nil {
		t.Error("ECH config record not found in cache")
	}
}
