# Blocklist sources: research

**Date:** 2026-10-12

Nobody can maintain "all ad servers" by hand. There are hundreds of thousands, and the malware and phishing domains change **hourly**. The plan therefore works in two layers:

1. **Upstream curated lists** are downloaded and compiled at runtime and refreshed every 24 h. This is where the real coverage comes from: about 300k–1.5M domains, depending on the preset.
2. **Built-in seed lists** in [`../blocklists/`](../blocklists/) ship inside the binary. They give immediate protection on first run, offline, before any download. They cover the largest, most stable ad/tracker networks I could identify, plus cryptojacking and telemetry categories. Seed lists deliberately contain **no** live malware/phishing domains: those go stale within days and must come from the threat feeds below.

> ✅ **Verified 2026-10-12 (M3).** Every URL marked *verify* below returned HTTP 200 and parsed. For OISD, `domainswild2` and `domainswild` both work, and ab-win uses `domainswild2`. Entry counts on that date: HaGeZi Light 55,914, Pro 193,076, Pro++ 206,596, TIF 1,907,239, TIF Medium 616,912, DoH 3,268, Windows/Office 383, OISD Big 237,859, AdGuard CNAME 240,632, Frogeye 1P 14,649, URLhaus 418. None contained a sentinel domain. The weekly `list-health` workflow re-checks this. The *verify* marks below are kept so this research can be traced.

---

## 1. Recommended upstream lists

### 1.1 Ads + trackers (general-purpose)

| List | Maintainer | Format | Approx. size | Licence | Use in preset | URL |
|---|---|---|---|---|---|---|
| **HaGeZi Multi Light** | hagezi | wildcard domains | ~100k | GPL-3.0 | Relaxed | `https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt` *(verify)* |
| **HaGeZi Multi Pro** | hagezi | wildcard domains / hosts | ~385k | GPL-3.0 | **Balanced (default)** | `https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt`; hosts variant: `…/main/hosts/pro.txt` |
| HaGeZi Multi Pro++ | hagezi | wildcard domains | larger | GPL-3.0 | Aggressive | `…/main/wildcard/pro.plus-onlydomains.txt` *(verify)* |
| **OISD Big** | sjhgvr / oisd.nl | wildcard domains (`domainswild2`) | ~200k+ | see oisd.nl | Aggressive (alternative to HaGeZi) | `https://big.oisd.nl/domainswild2` (sources disagree on `domainswild` versus `domainswild2`, so *verify*) |
| OISD Small | oisd.nl | wildcard domains | ~50k | see oisd.nl | Relaxed alternative | `https://small.oisd.nl/domainswild2` *(verify)* |
| **StevenBlack Unified hosts** | StevenBlack | hosts | ~80–160k | MIT | Fallback / reference | `https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts` |
| **AdGuard DNS filter** | AdGuard | ABP domain syntax (`\|\|d^`) | ~60k | GPL-3.0 | Balanced add-on | `https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt` |
| Peter Lowe's ad/tracking list | pgl.yoyo.org | hosts | ~3.5k | free use, read terms | Seed / Relaxed | `https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext` |
| EasyList / EasyPrivacy | easylist.to | ABP (browser syntax) | large | GPL-3.0 / CC BY-SA 3.0 | Only the `\|\|domain^` rules with no path or options are usable for DNS | `https://easylist.to/easylist/easylist.txt`, `https://easylist.to/easylist/easyprivacy.txt` |
| 1Hosts Lite | badmojr | domains | ~150k | MPL-2.0 | Alternative | `https://o0.pages.dev/Lite/domains.txt` *(verify)* |

**Choice for the Balanced default:** HaGeZi Multi Pro alone. Its maintainer explicitly targets low breakage and it already aggregates most of the lists above, so stacking many overlapping lists mainly adds false positives. The other lists are only offered in presets or as advanced toggles.

### 1.2 CNAME-cloaked (first-party) trackers

| List | Format | Licence | URL |
|---|---|---|---|
| AdGuard CNAME trackers | domains (tracker targets) | MIT | `https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_trackers_justdomains.txt` *(verify path)* |
| Frogeye first-party trackers | hosts | MIT | `https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt` |

These lists feed the CNAME un-cloaking check (PLAN section 3.3).

### 1.3 Malware, phishing, scam, cryptojacking

| List | Maintainer | Content | Update cadence | Licence | URL |
|---|---|---|---|---|---|
| **HaGeZi Threat Intelligence Feeds (TIF)** | hagezi | malware, phishing, scam, C2, cryptojacking (aggregates dozens of feeds). Quad9 also uses it. HaGeZi Pro **no longer fully includes TIF**, so add it separately. | several times a day | GPL-3.0 | `https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt`; hosts: `…/main/hosts/tif.txt` |
| HaGeZi TIF Medium / Mini | hagezi | smaller TIF subsets (recent threats only) | same | GPL-3.0 | `…/wildcard/tif.medium-onlydomains.txt` *(verify)* (low-memory fallback) |
| **URLhaus** (abuse.ch) | abuse.ch | malware distribution hosts | every few minutes upstream | CC0 | `https://urlhaus.abuse.ch/downloads/hostfile/` |
| urlhaus-filter (curben) | malware-filter project | URLhaus re-packaged as domains/hosts, with an "online-only" lite variant (~95% smaller) | twice a day | CC0 / MIT | `https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt` *(verify)* |
| phishing-filter (curben) | malware-filter project | phishing (PhishTank + OpenPhish + PhishStats) | twice a day | CC0 / MIT | `https://malware-filter.gitlab.io/malware-filter/phishing-filter-hosts.txt` *(verify)* |
| **ThreatFox** (abuse.ch) | abuse.ch | IOCs: C2, botnet, malware domains | hourly | CC0 | `https://threatfox.abuse.ch/downloads/hostfile/` *(verify)* |
| Phishing Army (extended) | phishing.army | phishing | daily | CC BY-NC 4.0 (**non-commercial**) | `https://phishing.army/download/phishing_army_blocklist_extended.txt` |
| HaGeZi Fake | hagezi | fake shops, scam, fake streaming | daily | GPL-3.0 | `…/wildcard/fake-onlydomains.txt` *(verify)* |
| NoCoin / cryptojacking | hoshsadiq | browser miners | rare (mostly a historical threat now) | MIT | `https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt` |
| Spamhaus DROP / EDROP | Spamhaus | **IP ranges**, not domains | daily | free, non-commercial | Not applicable to DNS. Candidate for a future Windows Firewall rule set. |

**Choice for the default malware category:** HaGeZi TIF plus URLhaus, with the default upstream resolver (Cloudflare `1.1.1.2`, the malware-blocking variant, with Quad9 as fallback) adding a second, independent threat-intel layer for free.

### 1.4 Windows and Microsoft telemetry (optional, off by default)

| List | Licence | URL |
|---|---|---|
| WindowsSpyBlocker (crazy-max), `spy` | MIT | `https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt` |
| HaGeZi Native Tracker: Windows/Office | GPL-3.0 | `…/wildcard/native.winoffice-onlydomains.txt` *(verify)* |

Warning shown in the UI: "May break Windows Update, Microsoft Store, Defender cloud protection, Office activation, or Xbox features."

### 1.5 DoH / VPN / proxy bypass (optional, off by default)

| List | URL |
|---|---|
| HaGeZi DoH only | `…/wildcard/doh-onlydomains.txt` *(verify)* |
| HaGeZi DoH/VPN/TOR/Proxy bypass | `…/wildcard/doh-vpn-proxy-bypass-onlydomains.txt` *(verify)* |

### 1.6 Allowlists (false-positive protection)

| List | Purpose |
|---|---|
| Our `blocklists/allowlist-default.txt` | Critical domains that must never be blocked: Windows Update, activation, NCSI connectivity check, certificate revocation (OCSP/CRL), major login and SSO providers |
| AnudeepND whitelist | Community list of commonly over-blocked domains, `https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt` (reference only, not enabled by default) |

---

## 2. Dead or unmaintained lists: do NOT use

Many tutorials still link these. Unmaintained lists contain expired domains (harmless but bloating) or, worse, domains that were later re-registered by legitimate owners (false positives).

| List | Status |
|---|---|
| hpHosts (hosts-file.net) | Shut down 2019 |
| MalwareDomains / DNS-BH (malwaredomains.com) | Shut down 2019–2020 |
| abuse.ch ZeuS Tracker | Discontinued 2019 |
| abuse.ch Ransomware Tracker | Discontinued 2019 |
| NoTracking (notracking/hosts-blocklists) | Archived; author recommends HaGeZi/OISD |
| Disconnect.me simple ad/tracking lists (s3.amazonaws.com/lists.disconnect.me) | Unmaintained for years |
| MVPS HOSTS | Rarely updated |
| Cameleon (sysctl.org/cameleon) | Unmaintained |
| CoinBlockerLists (ZeroDot1, GitLab) | Unmaintained since ~2022 |

---

## 3. Formats the compiler must parse

| Format | Example | Rule |
|---|---|---|
| hosts | `0.0.0.0 ads.example.com` / `127.0.0.1 ads.example.com` | Take the 2nd field. Ignore `localhost`, `local`, `broadcasthost`, `0.0.0.0` and `ip6-*`. |
| plain domains | `ads.example.com` | Exact name plus subdomains (our matching is always suffix-based) |
| wildcard | `*.ads.example.com` | Same as plain (strip `*.`) |
| ABP / AdGuard DNS | `\|\|ads.example.com^` | Accept only `\|\|domain^` with no path and no `$` options except `$important`. `@@\|\|domain^` means allow. Skip everything else (cosmetic `##`, regex `/…/`, paths). |
| comments | `#`, `!`, `[Adblock Plus …]` | Skip |

Normalisation: lower-case, trim the trailing `.`, convert IDN to punycode, validate LDH labels and length (≤ 253 total, ≤ 63 per label), drop entries with no dot. Deduplicate, and remove entries already covered by a blocked parent domain.

---

## 4. What's in the built-in seed lists

| File | Contents | Default |
|---|---|---|
| `blocklists/ads.txt` | Major ad networks, exchanges, SSPs/DSPs, ad verification, pop-under and native-ad networks, and in-app ad SDKs | on |
| `blocklists/trackers.txt` | Analytics, session recording, fingerprinting, data brokers, CNAME-cloaking tracker targets | on |
| `blocklists/malware-cryptojacking.txt` | Known browser-mining (cryptojacking) services, plus pointers to the live feeds. Live malware/phishing comes from TIF/URLhaus at runtime. | on |
| `blocklists/telemetry-windows.txt` | Microsoft/Windows telemetry endpoints | off |
| `blocklists/doh-bypass.txt` | Well-known public DoH endpoints | off |
| `blocklists/allowlist-default.txt` | Domains never blocked | always |

Seed lists use the plain-domain format: one domain per line, matching that domain and all its subdomains. In allowlists only, a `=` prefix means exact match (for example `=google.com` allows `google.com` but not `adservice.google.com`).

## Sources consulted

- [hagezi/dns-blocklists overview (2026)](https://blog.brightcoding.dev/2026/09/14/hagezidns-blocklists-tiered-dns-protection-for-ads-malware-tracking)
- [HaGeZi lists on Robtex](https://robtex.com/en/sources/hagezi-blocklists)
- [HaGeZi mirror](https://hagezi-mirror.dnsbunker.org/assets/dns-blocklists/)
- [NextDNS forum: TIF removed from Pro/Ultimate](https://help.nextdns.io/t/35y8w3j/idea-2-yearly-blocklist-maintenance)
- [Quad9 integrating HaGeZi TIF](https://forums.overclockers.co.uk/posts/38138261/)
- [Blacklisted domain lists compared (2026)](https://prospeo.io/s/blacklisted-domains-list)
- [Technitium issue on OISD formats](https://github.com/TechnitiumSoftware/DnsServer/issues/1441)
- [OISD feed implementation (happyDomain)](https://git.nemunai.re/happyDomain/checker-blacklist/commit/1242a381ab6241117188ed0eb33af8ab5a1017b5)
- [NextDNS: OISD](https://help.nextdns.io/t/g9hp76x/oisd)
- [curben/urlhaus-filter](https://git.nixnet.services/curben/urlhaus-filter/raw/commit/7000159da138c50665e37b3552d81bf24090da08/README.md)
- [URLhaus](https://urlhaus.abuse.ch/host/download-files-pdf.de)
- [CleanBrowsing: disabling DoH in browsers](https://cleanbrowsing.org/learn/how-to-disable-doh)
- [DNSFilter: disabling DoH on Windows and browsers](https://feedback.dnsfilter.com/feature-requests/p/disable-dns-over-https-in-chrome-edge-firefox-windows-native-networking)
- [Technitium blog: Firefox canary domain](https://blog.technitium.com/2020/07/)
- [Mozilla support: "Require DoH" policy breaks Firefox](https://support.mozilla.org/te/questions/1423913)
