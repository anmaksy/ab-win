# ab-win

A system-wide ad, tracker and malware blocker for Windows. It runs as a background service that filters DNS for **every browser and app**, with a tiny CLI and a tray icon to turn it on, off or pause it.

> **Status: planning.** No code yet. Start with the plan.

| Document | What's in it |
|---|---|
| [docs/PLAN.md](docs/PLAN.md) | Architecture, CLI and tray design, Windows service behaviour, testing, milestones, risks |
| [docs/BLOCKLIST-SOURCES.md](docs/BLOCKLIST-SOURCES.md) | Research on ad, tracker and malware lists: what to use, licences, formats, dead lists to avoid |
| [docs/USABILITY-REVIEW.md](docs/USABILITY-REVIEW.md) | Personas, task walkthroughs, heuristic evaluation, and the user test to run |
| [blocklists/](blocklists/) | Built-in offline seed lists (ads, trackers, cryptojacking, optional telemetry and DoH) plus the default allowlist |

**Planned install for friends:** download `ab-win.exe` from the GitHub Releases page, double-click it, click **Install**, and approve the admin prompt. That's it.

Planned CLI at a glance:

```
ab-win install           # service + autostart on boot (asks for admin once)
ab-win status
ab-win pause 15m         # auto-resumes
ab-win on | off
ab-win allow example.com
ab-win why ads.example.com
ab-win doctor
```

**What it can't do:** DNS blocking can't remove ads served from the same domain as the content, such as YouTube video ads or sponsored posts in social feeds. Use [uBlock Origin](https://github.com/gorhill/uBlock) in the browser alongside it.
