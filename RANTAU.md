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

Everything else is unchanged from the original release. The original's `.github` folder (its build, Docker,
Dependabot and issue settings) is not part of the apps and is left out here.
