package tls

import (
	"slices"
	"testing"
)

func TestECHDialFail(t *testing.T) {
	config := &Config{
		ServerName:    "cloudflare.com",
		EchConfigList: "udp://0.0.0.0",
	}
	tlsConfig := config.GetTLSConfig()
	ApplyECH(config, tlsConfig)
	if !slices.Equal(tlsConfig.EncryptedClientHelloConfigList, []byte{1, 1, 4, 5, 1, 4}) {
		t.Error("ECH config should be invalid when query failed", " but got ", tlsConfig.EncryptedClientHelloConfigList)
	}
}
