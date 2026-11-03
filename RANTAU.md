# Xray-core as built into Rantau VPN

This is the source of Xray-core [v26.10.31](https://github.com/XTLS/Xray-core/tree/v26.10.31) (commit
`a4a3dff5b20c2faae567b742c172c7b95e75c083`, Go module version
`v1.260327.1-0.20261031132019-a4a3dff5b20c`) used by Rantau VPN. Tag `v26.10.31-rantau.3` supplies the
exact source built into the Rantau VPN apps from their releases after Android 0.1.59 and macOS 0.2.48.
Those two, the first releases with Xray v26.10.31, use `v26.10.31-rantau.2` (their licence notices name
`v26.10.31-rantau.1`, which lacks the pre-connect trial build switch below). Earlier Android, macOS and
Windows releases retain their respective source tags (`v26.3.27-rantau`, `.2` and `.3`). This
source is published under Xray-core's own licence, the Mozilla Public License 2.0 ([LICENSE](LICENSE)).

## What differs from the original

The whole change is [xray-core.patch](xray-core.patch), applied with `patch -p1` to the original release.
Nothing is left out: since v26.9.30 Xray no longer uses the GPL-licensed
[sing](https://github.com/SagerNet/sing) library, so Shadowsocks 2022 and the rest of the original are
included as they are.

- **UDP/443 refusal.** The VLESS client rejects unsupported Vision UDP/443 after routing but before
  dialing, and the TUN inbound answers the application with an IPv4 ICMP port-unreachable that quotes
  only the original IP and UDP headers. Chinese/LAN direct UDP and explicitly enabled UDP443 remain
  supported. Aggregate counters record only association and refusal totals.
- **UDP destination isolation.** Each UDP source/destination pair has its own TUN association and
  routing decision, while reply source metadata (full cone) is preserved. Refusing one unsupported
  destination does not close another flow from the same application socket.
- **IPv6 refusal and deferred startup** (both opt-in, per instance). IPv6 TCP is answered with a reset
  and IPv6 UDP with ICMPv6 port unreachable, so applications fall back to IPv4. Packet reads can wait
  until the embedder has started the core and its outbounds (`Handler.Activate`). The handler's `Close`
  runs once. On Android a descriptor that cannot be set non-blocking is left to the application.
- **Demand-driven connection reserve** in place of the original `testpre` workers: at most two
  idle/in-flight sockets, two-second idle lifetime, three-second reserve dial timeout, immediate normal
  dialing when empty, and demand-driven cooldown after failures. Idle expiry never replenishes
  connections; handler shutdown cancels and drains owned work. Speculative REALITY authentication
  failures close the raw socket without detached camouflage requests, and unused TLS reserves close
  through the raw socket.
- **Pre-connect trial build switch.** The reserve's lifetime comes from `preconnect_policy.go` (two
  seconds, as above). A trial build with `-tags preconnect_trial` uses `preconnect_policy_trial.go`
  instead: spares wait 20 to 40 seconds and are checked through TLS just before use, falling back to a
  normal dial when the server has already closed them.
- **Instance shutdown.** Closing an instance ends the TUN stack's UDP flows (a packet still on its
  way opens none) and closes the DNS app's nameservers (UDP link and request timer, DoH idle
  connections), so a stopped instance is released at once instead of after their idle timeouts.
  The blackhole outbound's `Close` ends its blocked UDP flows, which otherwise waited 30 to 90 s of
  inactivity, and stops their inactivity timers.
- **Health-check reserve isolation.** A context marker lets health-check connections bypass
  application reserve lookup and refill; normal transport authentication is unchanged.
- **DNS answer when name servers disagree.** When the servers asked for a name fail differently (for
  example an answer that `expectedIPs` set aside, then "no such name" from the next server), the last
  server that answered decides the error, so the DNS outbound answers the client at once instead of
  sending nothing. When that server gave no DNS answer either, nothing is answered, as before.
- Regression tests for all of the above, next to the changed files.

These are correctness and resource-ownership changes; this source tag makes no application-speed or
network-performance claim. Other than these changes, the source matches the original release. The
original's `.github` folder (its build, Docker, Dependabot and issue settings) is not part of the apps
and is left out here.
