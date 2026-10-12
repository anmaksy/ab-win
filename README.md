# ab-win

Blocks ads, trackers and malware for **every browser and app on your Windows PC**. It runs quietly in the background and starts with Windows. A shield icon near the clock turns it on, off, or pauses it.

## Install (about a minute)

1. Go to the [Releases page](https://github.com/anmaksy/ab-win/releases/latest) and download **ab-win.exe**. (On an ARM PC, such as a Surface Pro X or Snapdragon laptop, use `ab-win-arm64.exe`.)
2. Double-click it and click **Yes** to "Install ab-win?".
   - If Windows says **"Windows protected your PC"**, click **More info → Run anyway**. That warning appears because the file isn't code-signed yet, not because something is wrong with it.
3. Click **Yes** when Windows asks for administrator approval.

That's it. A green shield appears near the clock (look under the **^** arrow if you don't see it).

| Shield | Meaning |
|---|---|
| Green with a check mark | Protected |
| Amber with pause bars | Paused; comes back on by itself |
| Grey with a dash | Off |
| Red with **!** | Problem; hover over it to see what's wrong |

## A site is broken?

Click the shield → **Recently blocked** → click the site's domain to **Allow** it, then reload the page.

## No internet?

ab-win is built so this shouldn't happen. If the service stops, Windows gets its normal DNS back within about two minutes. If the internet still doesn't work:

1. Download [restore-dns.ps1](scripts/restore-dns.ps1) (it's also on the Releases page).
2. Right-click it → **Run with PowerShell** → approve the admin prompt.

It puts your network settings back exactly as they were before ab-win and stops the service.

## Remove it

**Settings → Apps → Installed apps → ab-win → Uninstall**, or run `ab-win uninstall`. Your original DNS settings are restored.

---

## What it can't do

ab-win blocks requests to known ad, tracker and malware **domains**. It can't remove ads served from the same domain as the content: YouTube video ads, sponsored posts in Facebook or Instagram, Twitch ads, Google search ads. For those, also use [uBlock Origin](https://github.com/gorhill/uBlock) in your browser. The two work well together.

It's also not an antivirus. It stops connections to known-bad sites, which is one useful layer, not a replacement for Windows Security.

## Privacy

- Nothing is sent home. There's no telemetry and no account.
- The only network traffic is: your normal DNS lookups, encrypted to Cloudflare's malware-blocking resolver (Quad9 as fallback); blocklist downloads from GitHub and the list maintainers; and one daily check of this repo's Releases for a new version.
- The "recent lookups" log stays in memory only and is never written to disk. Turn it off with `query_log = false` in `C:\ProgramData\ab-win\config.toml`.

## For power users: the CLI

```
ab-win status                  # On/off/paused, blocked today, lists, DNS routing
ab-win pause [5m|1h|reboot]    # comes back on by itself (default 15m)
ab-win on | off
ab-win allow example.com       # never block (subdomains too); accepts a pasted URL
ab-win block example.com
ab-win why ads.example.com     # "blocked by: HaGeZi Pro (ads & trackers)"
ab-win recent --blocked -f     # live view of what's being blocked
ab-win lists                   # categories and lists
ab-win lists enable telemetry  # opt-in categories: telemetry, doh_bypass
ab-win preset aggressive       # relaxed | balanced (default) | aggressive
ab-win update                  # refresh blocklists now
ab-win doctor                  # "why isn't it blocking?"
ab-win harden-browsers         # stop Chrome/Edge/Brave/Firefox using their own DNS (--undo to revert)
ab-win lock on                 # only admins can turn it off (for a kid's PC)
ab-win self-update
```

Every read command takes `--json`. Exit codes: `0` ok, `1` error, `2` not installed, `3` needs admin (declined).

**Settings file:** `C:\ProgramData\ab-win\config.toml`. After editing it, run `ab-win reload`.

**Works alongside:** VPNs (a VPN that sets its own DNS takes over on its connection; `ab-win doctor` tells you), Docker and WSL (adapters without a gateway are left alone). It conflicts with anything else that serves DNS on port 53, such as Mobile hotspot / Internet Connection Sharing or another DNS filter. The installer names the program and stops instead of fighting over the port.

## How it works

ab-win runs a small DNS resolver on `127.0.0.1` as a Windows service and points your network adapters at it, saving your original settings first. Blocked names get `0.0.0.0` straight away. Everything else is forwarded over encrypted DNS (DoH) and cached. It also un-cloaks trackers hiding behind a site's own subdomain (CNAME checks), answers Firefox's DoH canary so Firefox keeps using system DNS, and sends local names (`fritz.box`, `*.lan`, your router's domain) to your router.

The details are in [docs/PLAN.md](docs/PLAN.md). The list research is in [docs/BLOCKLIST-SOURCES.md](docs/BLOCKLIST-SOURCES.md), and the usability review is in [docs/USABILITY-REVIEW.md](docs/USABILITY-REVIEW.md).

## Build from source

Requires Go (version in `go.mod`).

```
go test ./...
go build -o bin/ab-win.exe ./cmd/ab-win
bin\ab-win.exe run --data %TEMP%\abw     # foreground resolver on 127.0.0.1:53, no system changes
nslookup doubleclick.net 127.0.0.1       # → 0.0.0.0
```

`tests/service-e2e.ps1` exercises the real service: install, blocking, pause, crash recovery, watchdog failsafe and a clean uninstall. Run it as administrator **in a VM**. CI runs it on every push.

Releases: push a `v*` tag. GitHub Actions tests, builds amd64 and arm64, writes `SHA256SUMS` and an SBOM, and publishes the release.

## Credits and licences

ab-win's code and built-in seed lists are MIT-licensed. The upstream blocklists are downloaded at runtime and are never bundled: [HaGeZi DNS blocklists](https://github.com/hagezi/dns-blocklists) (GPL-3.0), [OISD](https://oisd.nl), [AdGuard CNAME trackers](https://github.com/AdguardTeam/cname-trackers) (MIT), [Frogeye first-party trackers](https://hostfiles.frogeye.fr) (MIT), [abuse.ch URLhaus](https://urlhaus.abuse.ch) (CC0). Thanks to their maintainers.
