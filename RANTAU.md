# Xray-core as built into Rantau VPN

This is the source of Xray-core [v26.3.27](https://github.com/XTLS/Xray-core/tree/v26.3.27) (Go module
version v1.260327.0) exactly as it is built into the Rantau VPN apps for Android, macOS and Windows. It is
published under Xray-core's own licence, the Mozilla Public License 2.0 ([LICENSE](LICENSE)).

## What differs from the original

Rantau VPN leaves out the parts of Xray-core that need the GPL-licensed
[sing](https://github.com/SagerNet/sing) library. The apps use VLESS with REALITY, so none of this changes
what they do.

**Left out:**
- Shadowsocks 2022 (`proxy/shadowsocks_2022`, `common/singbridge` and its test). Configurations that ask
  for a `2022-blake3-*` method get an error; classic Shadowsocks still works.
- UDP over TCP for Shadowsocks clients (`app/proxyman/outbound/uot.go`).
- The `github.com/sagernet/*` modules in `go.mod` and `go.sum`.

**Changed** (the whole change is [xray-core.patch](xray-core.patch), applied with `patch -p1` to the original):
- `transport/internet`: the socket hook type now comes from Xray itself, with the same shape as before.
- `proxy/wireguard/tun_linux.go`: binds to the interface with `SO_BINDTODEVICE` directly (Linux only; not
  part of any Rantau VPN app).
- `infra/conf/shadowsocks.go`, `app/proxyman/outbound/handler.go` and `main/commands/all/api`: the
  Shadowsocks 2022 and UDP-over-TCP branches are removed.

## Android 0.1.27 transport changes (v26.3.27-rantau.2)

- Reject unsupported Vision UDP/443 after routing but before dialing, and return an IPv4 ICMP
  port-unreachable from the TUN inbound. Chinese/LAN direct UDP and explicitly enabled UDP443
  remain supported. UDP send/close and stale association handling are synchronized.
- Replace the experimental blocking preconnect workers with an optional demand-driven reserve:
  at most two idle/in-flight sockets, two-second idle lifetime, three-second reserve dial timeout,
  immediate normal dialing when empty, and demand-driven cooldown after failures. Idle expiry
  never replenishes connections. Handler shutdown cancels and drains owned work.
- Clean up speculative REALITY authentication failures without detached camouflage requests.
  Close unused TLS reserves through the raw socket to avoid blocking foreground work.
- Add aggregate transport counters and regression tests for routing-independent refusal,
  concurrency, reserve ownership, cancellation, expiry and cleanup.

This tag supplies the changed Xray files for Rantau VPN Android 0.1.27. Earlier apps retain their
original source tag. The complete file set is mirrored from the vendored source used in that build.

Other than these changes and the removals listed above, the source matches the original release. The original's `.github` folder (its build, Docker,
Dependabot and issue settings) is not part of the apps and is left out here.
