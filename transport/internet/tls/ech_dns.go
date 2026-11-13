//go:build xray_ech_dns

package tls

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"
	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/net/http2"
)

// Rantau: moved from ech.go unchanged, so that only a copy built with -tags xray_ech_dns links a DNS
// library (miekg/dns) for ECH configs looked up over DNS (ech_dns_off.go stands in otherwise).

// dnsQuery is the real func for sending type65 query for given domain to given DNS server.
// return ECH config, TTL and error
func dnsQuery(server string, domain string, sockopt *internet.SocketConfig) ([]byte, uint32, error) {
	m := new(dns.Msg)
	var dnsResolve []byte
	m.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)
	// for DOH server
	if strings.HasPrefix(server, "https://") || strings.HasPrefix(server, "h2c://") {
		h2c := strings.HasPrefix(server, "h2c://")
		m.SetEdns0(4096, false) // 4096 is the buffer size, false means no DNSSEC
		padding := &dns.EDNS0_PADDING{Padding: make([]byte, int(crypto.RandBetween(100, 300)))}
		if opt := m.IsEdns0(); opt != nil {
			opt.Option = append(opt.Option, padding)
		}
		// always 0 in DOH
		m.Id = 0
		msg, err := m.Pack()
		if err != nil {
			return nil, 0, err
		}
		var client *http.Client
		serverKey := ECHCacheKey(server, "", sockopt)
		if client, _ = clientForECHDOH.Load(serverKey); client == nil {
			// All traffic sent by core should via xray's internet.DialSystem
			// This involves the behavior of some Android VPN GUI clients
			tr := &http2.Transport{
				IdleConnTimeout: net.ConnIdleTimeout,
				ReadIdleTimeout: net.ChromeH2KeepAlivePeriod,
				DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
					host, _, err := net.SplitHostPort(addr)
					if err != nil {
						return nil, err
					}
					dest, err := net.ParseDestination(network + ":" + addr)
					if err != nil {
						return nil, err
					}
					dnsCtx := ctx
					if h2c {
						dnsCtx = session.ContextWithMitmAlpn11(dnsCtx, false) // for insurance
						dnsCtx = session.ContextWithMitmServerName(dnsCtx, host)
					}
					var conn net.Conn
					conn, err = internet.DialSystem(dnsCtx, dest, sockopt)
					if err != nil {
						return nil, err
					}

					if !h2c {
						conn = utls.UClient(conn, &utls.Config{ServerName: host}, utls.HelloChrome_Auto)
						if err := conn.(*utls.UConn).HandshakeContext(ctx); err != nil {
							return nil, err
						}
					}
					return conn, nil
				},
			}
			c := &http.Client{
				Timeout:   30 * time.Second,
				Transport: tr,
			}
			client, _ = clientForECHDOH.LoadOrStore(serverKey, c)
		}
		req, err := http.NewRequest("POST", server, bytes.NewReader(msg))
		if err != nil {
			return nil, 0, err
		}
		// h2c: in config is just for claim
		// change scheme to https and expect outbound to handle TLS (freedom + tlsSetting)
		req.URL.Scheme = "https"
		req.Header.Set("Accept", "application/dns-message")
		req.Header.Set("Content-Type", "application/dns-message")
		utils.TryDefaultHeadersWith(req.Header, "fetch")
		req.Header.Set("X-Padding", utils.H2Base62Pad(crypto.RandBetween(100, 1000)))

		resp, err := client.Do(req)
		if err != nil {
			return nil, 0, err
		}
		defer resp.Body.Close()
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, 0, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, 0, errors.New("query failed with response code:", resp.StatusCode)
		}
		dnsResolve = respBody
	} else if strings.HasPrefix(server, "udp://") { // for classic udp dns server
		udpServerURL, err := url.Parse(server)
		if err != nil {
			return nil, 0, errors.New("failed to parse udp dns server ", server, " for ECH: ", err)
		}
		// default port 53 if not specified
		if udpServerURL.Port() == "" {
			udpServerURL.Host = udpServerURL.Host + ":53"
		}
		dest, err := net.ParseDestination("udp" + ":" + udpServerURL.Host)
		if err != nil {
			return nil, 0, errors.New("failed to parse udp dns server ", udpServerURL.Host, " for ECH: ", err)
		}
		dnsTimeoutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// use xray's internet.DialSystem as mentioned above
		conn, err := internet.DialSystem(dnsTimeoutCtx, dest, sockopt)
		if err != nil {
			return nil, 0, err
		}
		defer func() {
			err := conn.Close()
			if err != nil {
				errors.LogDebug(context.Background(), "Failed to close connection: ", err)
			}
		}()
		msg, err := m.Pack()
		if err != nil {
			return nil, 0, err
		}
		conn.Write(msg)
		udpResponse := make([]byte, 512)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err = conn.Read(udpResponse)
		if err != nil {
			return nil, 0, err
		}
		dnsResolve = udpResponse
	}
	respMsg := new(dns.Msg)
	err := respMsg.Unpack(dnsResolve)
	if err != nil {
		return nil, 0, errors.New("failed to unpack dns response for ECH: ", err)
	}
	if len(respMsg.Answer) > 0 {
		for _, answer := range respMsg.Answer {
			if https, ok := answer.(*dns.HTTPS); ok && https.Hdr.Name == dns.Fqdn(domain) {
				for _, v := range https.Value {
					if echConfig, ok := v.(*dns.SVCBECHConfig); ok {
						errors.LogDebug(context.Background(), "Get ECH config:", echConfig.String(), " TTL:", respMsg.Answer[0].Header().Ttl)
						return echConfig.ECH, answer.Header().Ttl, nil
					}
				}
			}
		}
	}
	return nil, 0, errors.New("no valid ECH config found in DNS response")
}
