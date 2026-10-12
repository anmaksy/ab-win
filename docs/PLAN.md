# adblock-win — Plan

**Status:** Planning. No code yet.
**Date:** 2026-10-12
**Goal:** A Windows background service that blocks ads, trackers and malware/phishing domains for the whole OS, so it works in every browser (Chrome, Edge, Firefox, Brave, Opera, Vivaldi…) and in every other app, with a tiny CLI and a tray icon to turn it on and off.

Related documents:
- [BLOCKLIST-SOURCES.md](BLOCKLIST-SOURCES.md): research on upstream ad, tracker and malware lists (sources, licences, formats, dead lists to avoid).
- [USABILITY-REVIEW.md](USABILITY-REVIEW.md): the usability checks the design was put through, and what changed because of them.
- [`../blocklists/`](../blocklists/): built-in seed lists that ship with the binary and work offline.

---

## 1. What this product is and isn't

**It does:**
- Block requests to known ad, tracker, malware, phishing, scam and cryptojacking **domains** for the whole system. Every browser and app that uses system DNS is covered.
- Run as a Windows service that starts automatically on boot.
- Offer `on`, `off` and `pause` from a CLI and from a tray icon. A pause always ends on its own.
- Update its blocklists automatically from curated upstream sources.

**It does not do (DNS-level filtering cannot):**
- Remove ads served from the same domain as the content. Examples: YouTube video ads, Facebook/Instagram sponsored posts, Twitch embedded ads, Google search ads. A browser extension (uBlock Origin) is still needed for those. The README will say so up front so users aren't disappointed.
- Cosmetic filtering, meaning hiding empty ad boxes on a page.
- Block apps that hard-code their own DNS servers or DNS-over-HTTPS. Mitigation is in section 6.
- Replace an antivirus. Malware blocking here means not connecting to known-bad domains. It is one layer, not a scanner.

## 2. Approach decision

| Option | How it works | Verdict |
|---|---|---|
| **A. Edit the `hosts` file** | Write `0.0.0.0 domain` lines to `C:\Windows\System32\drivers\etc\hosts` | ❌ Rejected as the main approach. Very large hosts files (100k+ lines) make the Windows DNS Client service slow or hang. There are no wildcards, so every subdomain needs its own line. There are no stats and no per-domain "why was this blocked". Defender flags hosts files that block Microsoft domains (`SettingsModifier:Win32/HostsFileHijack`). Toggling means rewriting a system file. |
| **B. Local DNS resolver service** | The service listens on `127.0.0.1:53` and `[::1]:53`. Windows sends all DNS there. Blocked names get `0.0.0.0` / `::`. Everything else is forwarded upstream (DoH by default). | ✅ **Chosen.** Supports wildcards, millions of domains in about 50 MB, instant on/off, stats and a query log. CNAME un-cloaking is possible. It is the proven design used by Pi-hole, AdGuard Home, Technitium and NextDNS CLI. |
| C. WFP kernel driver / HTTPS-inspecting proxy | Filter packets or MITM TLS | ❌ Rejected for v1. Needs a signed kernel driver or a root CA installed on the machine. High risk, high complexity, and a weaker security posture. |
| D. Browser extensions | One per browser | ❌ This isn't OS-level, which the brief requires. We will recommend uBlock Origin as a complement. |

### 2.1 How DNS gets routed to the service

There are two ways to make Windows use `127.0.0.1`. **Milestone M0 is a spike that decides between them:**

1. **Set adapter DNS.** Set every active adapter's DNS to `127.0.0.1` / `::1` with `SetInterfaceDnsSettings` or WMI, then restore the original settings when protection is turned off.
   - Pros: simple and well understood.
   - Cons: VPN clients and new adapters (Wi-Fi hotspots, USB tethering) can override the setting, so we must watch for network changes (`NotifyIpInterfaceChange`) and re-apply. We must also save and restore DHCP versus static DNS correctly.
2. **NRPT rule.** Add a Name Resolution Policy Table catch-all rule (`Namespace "."` → `127.0.0.1`).
   - Pros: applies to all adapters, survives most VPN/adapter changes, and toggling it is a single rule.
   - Cons: less common and needs validation on Windows 10 22H2 and 11 24H2/25H2. Some corporate VPNs also push NRPT rules.

**Fallback rule (both options):** never configure a public DNS server as a secondary. Windows would silently use it and bypass blocking. Instead, make sure that if the service dies, the original DNS is restored (see section 5.4).

### 2.2 Language and stack

**Go**, as a single static `adblock.exe` with no runtime to install:
- `golang.org/x/sys/windows/svc`: Windows service.
- `github.com/miekg/dns`: DNS server and client (battle-tested; used by CoreDNS).
- DoH/DoT upstream: standard library `net/http` plus HTTP/2.
- Tray: `fyne.io/systray` (or `getlantern/systray`).
- IPC: a named pipe (`\\.\pipe\adblock-win`) via `github.com/Microsoft/go-winio`, with an explicit ACL.
- Config: TOML in `C:\ProgramData\adblock-win\config.toml`.

Considered alternative: **.NET 8 + WinUI/WinForms**. It gives a nicer native UI, but the service must start very early at boot and stay small, and Go's single binary and simple cross-compilation fit better. The UI can be rewritten later without touching the core.

## 3. Architecture

```
                         ┌──────────────────────────────────────────────┐
  Browsers / apps        │  adblock.exe  (Windows service, LocalSystem) │
  ─────────────────▶ DNS │                                              │
  Windows DNS Client ───▶│  DNS listener 127.0.0.1:53, [::1]:53 (UDP/TCP)│
  (Dnscache)             │      │                                       │
                         │      ▼                                       │
                         │  Policy engine                               │
                         │   1. allowlist (user > built-in)             │
                         │   2. user blocklist                          │
                         │   3. compiled lists (domain trie, wildcard)  │
                         │   4. CNAME chain check on upstream answers   │
                         │      │ blocked → 0.0.0.0 / :: (TTL 60)       │
                         │      │ allowed ▼                              │
                         │  Cache (LRU, respects TTL, prefetch)         │
                         │      ▼                                       │
                         │  Upstream: DoH (Cloudflare → Quad9 fallback) │
                         │                                              │
                         │  List updater (every 24h, ETag, atomic swap) │
                         │  Network watcher (re-apply DNS redirection)  │
                         │  Stats + ring-buffer query log (in memory)   │
                         │  IPC server  \\.\pipe\adblock-win            │
                         └───────────────▲──────────────────────────────┘
                                         │ JSON-RPC over named pipe
                    ┌────────────────────┴───────────────────┐
                    │ adblock.exe (CLI)   adblock.exe tray   │
                    └────────────────────────────────────────┘
```

### 3.1 Components

| Component | Responsibility | Notes |
|---|---|---|
| `dnsserver` | Listens on UDP and TCP 53 (v4 and v6) | Only on loopback, never on the LAN, so we can't become an open resolver. |
| `policy` | Decides block or allow for a name | Lookups walk a **reversed-label trie** or a hash set of suffixes: `a.b.ads.example.com` checks `com`, `example.com`, `ads.example.com` and so on. That costs O(labels) per lookup. Target: < 5 µs per lookup with 1.5M domains. |
| `compiler` | Turns raw lists into a deduplicated binary snapshot | Parses hosts, plain domain and ABP-style (`\|\|domain^`) formats. Drops entries already covered by a parent domain. Writes `lists.bin` so startup takes < 300 ms without network. |
| `upstream` | Forwards allowed queries | DoH to **Cloudflare's malware-blocking resolver** (`security.cloudflare-dns.com`, `1.1.1.2` / `1.0.0.2`) by default. It's the same fast anycast network as `1.1.1.1` but adds a free second malware filter. **Quad9** (`9.9.9.9`) is the automatic fallback. Config: `upstream = cloudflare-security \| cloudflare \| quad9 \| system`. `system` uses the original DHCP DNS over plain UDP, for networks that need it. |
| `cache` | Positive and negative cache | Caps TTLs and serves stale entries while refreshing. |
| `netwatch` | Keeps DNS pointed at loopback | Re-applies on adapter change, VPN connect and resume from sleep. |
| `captive` | Handles hotel/airport Wi-Fi portals | Detects captive portals (the Windows NCSI probe `www.msftconnecttest.com` and HTTP 302s). While a portal is detected, forwards plain DNS to the DHCP-provided server. |
| `updater` | Fetches upstream lists | Conditional GET (ETag/Last-Modified) and per-list SHA-256 logging. Sanity checks: reject an update that shrinks a list by > 50% or grows it by > 300%, or that contains one of the exact-match sentinel domains in `allowlist-default.txt` (`google.com`, `microsoft.com`, …) (protects against broken or poisoned lists). Swaps atomically. |
| `ipc` | Named-pipe JSON-RPC | Pipe ACL: SYSTEM and Administrators get full control. **By default, any interactive user can read status, toggle, pause and allow or block domains.** The optional `lock_settings = true` restricts changes to admins (for a kid's PC). |
| `stats` | Counters and query log | In-memory ring buffer of the last 10k queries by default. The query log **can be turned off** and is never written to disk unless the user enables it, for privacy. |

### 3.2 Block response

- `A` → `0.0.0.0`, `AAAA` → `::`, TTL 60 s. This fails instantly; NXDOMAIN makes some apps retry, and a fake IP makes browsers hang.
- `HTTPS`/`SVCB` (type 65/64) → empty NOERROR. This matters: Chrome and Firefox query HTTPS records, and an answer could leak ECH or alt-svc hints.
- A response flag in the stats records which list blocked the name, so `adblock why <domain>` works.

### 3.3 CNAME un-cloaking

Trackers hide behind first-party subdomains (`metrics.shop.com CNAME shop.eulerian.net`). After the upstream answers, walk the CNAME chain. If any target is blocked, block the original name. Supporting lists: AdGuard `cname-trackers` and the Frogeye first-party list (see BLOCKLIST-SOURCES.md).

### 3.4 Files on disk

```
C:\Program Files\adblock-win\adblock.exe
C:\ProgramData\adblock-win\
    config.toml          # settings (ACL: Admins write, Users read)
    allow.txt            # user allowlist, one domain per line
    block.txt            # user blocklist
    lists\*.txt          # raw downloaded lists (cache)
    lists.bin            # compiled snapshot
    state.json           # saved original DNS settings per adapter (for restore)
    logs\adblock.log     # service log, rotated, 5 × 5 MB
```

## 4. User interface

### 4.1 CLI (`adblock`)

The design rule: the 3 most common tasks are single, obvious words. Everything else is discoverable with `adblock help`.

```
adblock status                 # On/Off/Paused, blocked today, lists age, DNS routing OK?
adblock on                     # enable protection
adblock off                    # disable (asks "pause instead?" hint once)
adblock pause [15m|1h|reboot]  # temporary off, auto-resumes (default 15m)

adblock allow <domain>         # never block this domain (and subdomains)
adblock block <domain>         # always block
adblock unallow / unblock <domain>
adblock why <domain>           # "blocked by: HaGeZi Pro (ads)" or "allowed"
adblock recent [--blocked] [-f]# last queries, live follow with -f

adblock lists                  # show lists, enabled state, size, last update
adblock lists enable|disable <name>
adblock update                 # refresh lists now

adblock install                # install + start service, autostart on boot (elevates via UAC)
adblock uninstall              # stop, restore original DNS, remove service
adblock doctor                 # diagnose: port 53 conflict, DoH bypass, VPN, adapters, upstream reachability
adblock harden-browsers [--undo]  # opt-in: set DoH-off policies for Chrome/Edge/Brave/Firefox
```

Conventions:
- Every command that changes state prints the new state in one line, for example `✔ Protection paused — resumes at 14:35 (in 15 min)`.
- `--json` on every read command, for scripting.
- Exit codes: `0` ok, `1` error, `2` service not installed, `3` needs elevation.
- Commands that need admin (`install`, `uninstall`, `harden-browsers`) re-launch themselves elevated through UAC instead of failing with "access denied".
- `NO_COLOR` is respected, and no emoji appear when stdout isn't a TTY.

### 4.2 Tray app (`adblock tray`, auto-starts at user logon)

```
 [🛡 green]  adblock-win — Protected
 ─────────────────────────────────
 ● Protection on            (click toggles)
   Pause  ▸  5 minutes / 1 hour / Until restart
 ─────────────────────────────────
   Blocked today: 4 812
   Recently blocked  ▸  (last 10 domains → click = "Allow this domain")
 ─────────────────────────────────
   Update lists now
   Settings…            (opens config folder / small web page on 127.0.0.1)
   About / Help
   Quit tray (protection keeps running)
```

- Icon states: **green shield** = on, **grey shield** = off, **amber shield with clock** = paused, **red shield with !** = problem (for example DNS hijacked by a VPN, or the service not running). Every state also carries a text tooltip, so colour isn't the only signal.
- **"Recently blocked → Allow"** is the single most important ease-of-use feature. The most common real-world problem is "a site broke", and this fixes it in two clicks without knowing what DNS is.
- When the service isn't installed, the tray offers a one-click "Install protection".

### 4.3 Optional later: local dashboard

A small HTML page served on `http://127.0.0.1:5380`, protected by a random token that the tray passes. It shows stats, the query log, lists and the allowlist. This is out of scope for v1, but keep the IPC API shaped so it's easy to add.

## 5. Service behaviour on Windows

### 5.1 Install

- `adblock install` (or double-clicking `adblock.exe`, see section 5.6) does the following:
  1. Copies the binary to `Program Files`.
  2. Registers the service `adblock-win` with start type **Automatic** (not Delayed: DNS is needed early), runs it as LocalSystem, and sets recovery to *restart after 5 s, 10 s, 30 s*.
  3. Saves the current DNS settings per adapter to `state.json`.
  4. Starts the service.
  5. Points DNS at loopback.
  6. Registers the tray to run at logon for **all users** (HKLM `Run` key), because a friend's PC may have several accounts.
  7. Registers an uninstall entry under "Installed apps" that runs `adblock uninstall`.
- Before taking port 53, check whether something else holds it: ICS/`SharedAccess`, Hyper-V's default switch DNS proxy, Docker Desktop, another DNS filter (AdGuard, Simple DNSCrypt, Acrylic). If so, explain clearly and stop. Don't fight over the port.
- Distribution: see section 5.6.

### 5.2 On / off semantics

- **Off/pause** keeps the service running but switches the policy to "allow all". DNS stays on loopback, so turning it back on is instant and nothing is reconfigured. Users can't tell the difference, and there's no risk of leaving DNS broken.
- **Uninstall** is the only path that restores the original adapter DNS and removes the NRPT rule.

### 5.3 Boot order

The service starts before user logon. Until the compiled `lists.bin` is loaded (< 300 ms), it forwards queries unfiltered rather than failing. Network must never be blocked by our own startup.

### 5.4 Failsafe (the most important robustness requirement)

If the service crashes, or Windows stops it, DNS on loopback would mean **no internet at all**. The service handles this in several layers:
- Service recovery restarts it within 5 s.
- After 3 crashes within 10 minutes, a watchdog (a scheduled task, or the tray process) restores the original DNS from `state.json` and shows the tray in the red "problem" state.
- `adblock uninstall` restores DNS even if the service is already gone.
- The installer ships a standalone `restore-dns.ps1` as a last-resort recovery script, documented in the README.

### 5.5 Sleep, resume, network change, VPN

- Re-check routing on `PBT_APMRESUMEAUTOMATIC` and on interface change notifications.
- Flush the Windows DNS cache (`DnsFlushResolverCache`) whenever protection is toggled or the lists change, so the effect is immediate.
- VPNs:
  - If a VPN sets its own DNS, `doctor` and the tray report "VPN is handling DNS — blocking inactive on that connection".
  - An option to force loopback on VPN adapters is **off by default**, because it breaks split-DNS on corporate VPNs.

### 5.6 Sharing with friends (distribution)

Decision: the repo is shared so friends can install it themselves. The target is that a non-technical friend installs it from the GitHub Releases page in under a minute.

- **Release pipeline:** pushing a `v*` tag runs GitHub Actions. It builds `adblock.exe` (amd64 and arm64), runs the full test suite and attaches the binaries plus `SHA256SUMS` to a GitHub Release.
- **One file, double-click install:** running `adblock.exe` with no arguments when the service isn't installed shows "Install adblock-win? It blocks ads and malware for all apps." Clicking **Install** brings up the UAC prompt; protection then turns on and the tray icon appears. No terminal is needed. The CLI stays available for power users.
- **App updates:** the service checks the GitHub Releases API once a day. This and the list downloads are its only outbound calls. When a new version exists, the tray shows "Update available". Clicking it downloads the new binary, verifies the SHA-256 (and the signature, once releases are signed), and swaps it in place, keeping the old binary for rollback. `adblock self-update` does the same from the CLI.
- **SmartScreen:** an unsigned exe downloaded from GitHub shows "Windows protected your PC". The plan is staged:
  1. **Start unsigned.** The README shows a screenshot of "More info → Run anyway", and `SHA256SUMS` lets careful friends verify the download. That's acceptable for a circle of friends.
  2. **If it spreads further,** sign releases in CI with Azure Trusted Signing (low monthly cost; check individual-developer eligibility at that time) or an OV certificate.
- **Later and optional:** a winget manifest (`winget install adblock-win`) and an MSI. Neither is needed for friends.
- **Licence:** MIT for our code and seed lists. Upstream lists (GPL-3.0, CC BY-NC and others) are **downloaded at runtime, never committed or bundled**, so their licences don't constrain the repo. The About dialog credits them.
- **README for friends:** the first screen covers install in three steps, then "A site is broken?" (tray → Recently blocked → Allow), then "No internet?" (`restore-dns.ps1`).

## 6. Keeping browsers honest (DoH bypass)

Browsers can skip system DNS by using their own DNS-over-HTTPS.

| Browser | Default behaviour | Our mitigation |
|---|---|---|
| Chrome / Edge / Brave / Opera / Vivaldi (Chromium) | "Secure DNS" in automatic mode only upgrades if the *system* resolver is a known DoH provider. With `127.0.0.1` it doesn't, so we're fine by default. | If the user manually picked a custom DoH provider, `doctor` detects it. `harden-browsers` sets policy `DnsOverHttpsMode = "off"` under `HKLM\SOFTWARE\Policies\Google\Chrome`, `…\Microsoft\Edge` and `…\BraveSoftware\Brave`. |
| Firefox | DoH (TRR) is on by default in some regions. | Answer the canary domain `use-application-dns.net` with NXDOMAIN. Firefox then disables its default DoH. `harden-browsers` sets the policy `DNSOverHTTPS: {Enabled: false, Locked: true}`. |
| All apps | Hard-coded DoH (`dns.google`, `cloudflare-dns.com`, …) | Optional list category **"Block DoH/VPN bypass"** (HaGeZi `doh` list), **off by default** because it also breaks legitimate privacy tools. |

The browser policies make Chrome and Edge show "Managed by your organization". `harden-browsers` is therefore **opt-in**, explains this before applying, and has `--undo`.

Windows' own DoH client (Windows 11) isn't a problem. It only encrypts towards the configured DNS server, which is us.

## 7. Block categories (user-facing)

Users pick categories, not raw lists. Each category maps to upstream lists (see BLOCKLIST-SOURCES.md).

| Category | Default | Contents |
|---|---|---|
| Ads | ✅ on | Ad servers, ad networks, ad exchanges |
| Trackers & analytics | ✅ on | Analytics, fingerprinting, CNAME-cloaked trackers |
| Malware, phishing, scams | ✅ on | Threat-intel feeds (abuse.ch, HaGeZi TIF, phishing lists), cryptojacking |
| Windows & Office telemetry | ⬜ off | Microsoft telemetry endpoints. Off by default because it can break Windows Update, Store, Defender cloud protection and Office activation. |
| Affiliate & tracking redirects | ⬜ off | Affiliate link redirectors, monetised link shorteners. Off by default because blocking them breaks links users deliberately click. |
| DoH / VPN / proxy bypass | ⬜ off | See section 6 |
| Gambling / adult | ⬜ off | Future, for family use |

Strength presets: **Balanced** (default: HaGeZi Pro + TIF), **Relaxed** (HaGeZi Light + TIF), **Aggressive** (HaGeZi Pro++ + OISD Big + more). Users who never open settings get Balanced, which is tuned for very low breakage.

## 8. Testing plan

### 8.1 Automated

| Level | What | How |
|---|---|---|
| Unit | List parsers (hosts, domains, ABP, wildcard, comments, IDN/punycode, CRLF, BOM), trie matching, allow-over-block precedence, CNAME logic, config migration | `go test`, table-driven, plus fuzzing (`go test -fuzz`) on parsers and the DNS message handling |
| Integration | Real DNS server on a random port: A/AAAA/HTTPS/CNAME/TCP fallback/truncation, upstream timeout → fallback, cache TTL, stale serving | `go test` with a fake upstream |
| Service | install → start → query → pause → auto-resume → uninstall restores DNS exactly (DHCP vs static, IPv4 and IPv6) | GitHub Actions `windows-latest` (admin available) plus a Windows 10 22H2 VM |
| Failsafe | Kill the service process; machine still resolves within N s after watchdog. Corrupt `lists.bin` → rebuilt. Poisoned list update rejected. | Scripted chaos tests |
| Browser E2E | Chrome, Edge, Firefox, Brave: load a test page that references known ad/tracker domains plus our own test domain `blocked.adblock-win.test`. Assert the requests fail and the page loads. Repeat with Firefox TRR enabled to verify the canary. | Playwright (Chromium, Edge channel, Firefox) |
| Breakage | Top 200 sites (login, checkout, video) load with no console errors caused by DNS blocks. Diff against protection-off. | Nightly Playwright job; failures produce allowlist candidates |
| Performance | p50/p99 query latency (cached < 1 ms, uncached ≈ upstream + 2 ms), memory with 1.5M domains (< 80 MB), startup < 300 ms, CPU idle ≈ 0 | `go test -bench`, `dnsperf`-style load |
| List health | Every upstream URL still returns 200, parses, and its size is within expected bounds | Weekly CI job; opens an issue when a list dies |

### 8.2 Manual release checklist

- Fresh Windows 11 VM: download `adblock.exe` from the GitHub Release, double-click it, get past SmartScreen following only the README, and install. Repeat on a non-admin account, where toggle, pause and allow must also work.
- Wi-Fi ↔ Ethernet switch, sleep/resume, captive portal (simulated), common VPN (WireGuard, OpenVPN), Docker Desktop installed, Hyper-V enabled.
- Uninstall leaves no service, no NRPT rule, the original DNS and no leftover tray `Run` key.

## 9. Security and privacy

- Listens only on loopback, never on `0.0.0.0`, so we can't be an open resolver on public Wi-Fi.
- Nothing is sent home. There is no telemetry, by design and stated in the README. The only network traffic is list downloads (HTTPS) and upstream DNS.
- List downloads are HTTPS-only, size-limited (max 50 MB per list) and sanity-checked (section 3.1, `updater`). Domains are validated by the parser (charset, length, label rules), so a hostile list can't inject garbage.
- Named-pipe ACL as in section 3.1. By default any interactive user can toggle. With `lock_settings = true`, only admins can.
- Self-update downloads only from this repo's GitHub Releases over HTTPS and checks the SHA-256 before swapping binaries.
- The DNS parser is fuzzed. Responses are size-capped and request rates limited per process.
- Signed binaries. Reproducible builds (`-trimpath`). SBOM published with each release.

## 10. Milestones

| # | Milestone | Deliverable | Exit criteria |
|---|---|---|---|
| M0 | **Spike** (2–3 days) | Prototype: loopback DNS plus adapter-DNS versus NRPT routing, on Win10 and Win11 | Choose a routing method. Confirm the browser canary behaviour. List the port-53 conflicts we found. |
| M1 | Core resolver | `dnsserver`, `policy`, `compiler`, `upstream`, `cache` + unit and integration tests | Blocks the seed lists in a foreground console run (`adblock run`) |
| M2 | Service + CLI | Service install/uninstall, IPC, all CLI commands except `harden-browsers`, failsafe | Service tests green. Uninstall restores DNS. |
| M3 | Lists | Updater, categories, presets, list-health CI | Balanced preset passes the breakage suite |
| M4 | Tray | Tray app, icon states, recently blocked → allow, pause menu | Usability walkthrough tasks done in < 30 s (see USABILITY-REVIEW.md) |
| M5 | Hardening | CNAME un-cloaking, `doctor`, `harden-browsers`, captive portal, VPN detection | Browser E2E green with Firefox TRR on |
| M6 | Distribution | GitHub Actions release pipeline, double-click installer, self-update, friend-facing README, `restore-dns.ps1`, MIT licence | Fresh-VM install works following only the README; usability review re-run on the built app |
| M7 | Beta | 2–4 weeks of daily use on 3–5 machines | No unrecoverable DNS outage. Allowlist defaults updated from real breakage. |

## 11. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Service crash leaves the machine with no DNS | High: "my internet is broken" | Failsafe in section 5.4. Pause and off never touch adapter config. |
| Over-blocking breaks sites | Medium: users disable it permanently | Balanced default, built-in allowlist, two-click allow from the tray, breakage CI |
| An upstream list goes bad or dies | Medium | Sanity checks, last-known-good snapshot, list-health CI, several sources per category |
| Port 53 conflict (ICS, Hyper-V, Docker) | Medium | Detect and explain in `install` and `doctor`. Optional alternate approach in a later version (NRPT to `127.0.0.53`?) |
| VPN or corporate policy overrides DNS | Low/Medium | Detect and tell the user. Don't fight corporate IT. |
| SmartScreen or antivirus flags the unsigned binary or the DNS changes | Medium | README walkthrough and `SHA256SUMS` first; code signing if it spreads (section 5.6). No hosts-file edits. Clear product description. |
| Licence of upstream lists (GPL/CC BY-SA) | Low | Download at runtime instead of redistributing. Bundle only our own seed lists plus permissive ones. Attribute in About. |

## 12. Decisions (2026-10-12)

| Question | Decision | Effect on the plan |
|---|---|---|
| Personal use or shared? | **Shared:** friends install it from the GitHub repo | Section 5.6: GitHub Releases, double-click install, self-update, staged code signing, MIT licence |
| Can non-admin users turn it off? | **Yes** | The default pipe ACL lets any interactive user toggle. `lock_settings` stays an opt-in for kids' PCs. |
| Upstream DNS | **Cloudflare** (for speed); Quad9 acceptable | Default is `security.cloudflare-dns.com` (1.1.1.2, malware-blocking, same speed). Quad9 is the fallback. |
| LAN mode (phones, TVs) | **No, skip** | The listener stays loopback-only for good. The smart-TV category is removed. Out of scope. |
