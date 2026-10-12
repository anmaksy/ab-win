# Usability review of the design

**Date:** 2026-10-12
**Scope:** The CLI and tray design in [PLAN.md](PLAN.md), sections 4–6.
**Honesty note:** This is a **design-stage** review, done before any code exists. It used a cognitive walkthrough, a heuristic evaluation and a predicted SUS score. It is not a study with real users. The review is repeated on the built app at M4 and M6.

---

## 1. Personas

| Persona | Description | What they need |
|---|---|---|
| **P1: Non-technical home user** | Uses Chrome and Edge, doesn't know what DNS is, gets the app from a friend | Install once, forget it exists, fix a broken site without help |
| **P2: Power user / developer** | Uses Firefox and Brave, runs Docker and a VPN, lives in a terminal | Scriptable CLI, "why was this blocked", no conflicts with dev tools |
| **P3: Parent / family admin** | Sets up a kid's PC | Protection the kid can't switch off, malware and scam blocking |

## 2. Cognitive walkthrough: key tasks

For each step: Will the user know what to do? Will they see the control? Will they connect the control to their goal? Will they understand the feedback?

| # | Task | Persona | Path in the **first draft** | Problem found | Fix adopted in PLAN.md | Target time |
|---|---|---|---|---|---|---|
| T1 | Install and turn on protection | P1 (a friend) | Download zip → open terminal as admin → `adblock install` | P1 won't open an admin terminal. "Access denied" is a dead end. The unsigned exe triggers a SmartScreen warning. | **Double-click `adblock.exe` from GitHub Releases → Install → UAC** (section 5.6). `adblock install` self-elevates. README screenshot for "More info → Run anyway". | < 60 s |
| T2 | Check that it's working | P1 | `adblock status` | P1 never opens a terminal | Tray icon colour, **plus** a text tooltip, plus a "Blocked today: N" counter as visible proof of value (section 4.2) | < 5 s |
| T3 | A site is broken, fix it | P1 | `adblock recent --blocked` → find domain → `adblock allow x` | Needs DNS knowledge. This is the #1 reason people uninstall ad blockers. | Tray → **Recently blocked → click → Allow** (2 clicks). `adblock why <domain>` for P2. | < 30 s |
| T4 | Temporarily turn it off | P1/P2 | `adblock off` | Users forget to turn it back on, so protection silently stays off for weeks | **Pause** with auto-resume is the primary action (5 min / 1 h / until restart). `off` hints at `pause` once. The tray shows an amber "paused" state with the resume time. | < 5 s |
| T5 | Turning off must not break internet | all | Draft: off = restore adapter DNS | Restoring DNS on every toggle is slow and fragile, and a crash midway leaves no DNS | Off and pause **only change the policy**. DNS routing stays on loopback, and only uninstall restores it (section 5.2). | instant |
| T6 | Uninstall cleanly | P1 | Draft: delete the folder | Leaves DNS pointing at a dead loopback, so there's no internet | Uninstalling from Windows "Installed apps" or with `adblock uninstall` restores DNS. `restore-dns.ps1` is documented as a last resort. The watchdog restores DNS after repeated crashes (section 5.4). | < 60 s |
| T7 | It isn't blocking in Firefox | P2 | No path | Silent failure: Firefox DoH bypasses us | Canary domain by default. `adblock doctor` explains the cause and offers `harden-browsers` (section 6). | < 2 min |
| T8 | Docker or Hyper-V conflict | P2 | Install fails with "bind: address in use" | Cryptic error | Port-53 pre-check names the conflicting service and suggests a fix (section 5.1) | < 2 min |
| T9 | Stop the kid from turning it off | P3 | No path | Any user can pause it | `lock_settings = true`: the pipe ACL only lets admins toggle. The tray shows "Managed by administrator" instead of greyed-out mystery buttons. | < 2 min |
| T10 | Script it | P2 | Parse text output | Brittle | `--json` on every read command, stable exit codes (section 4.1) | — |

## 3. Heuristic evaluation (Nielsen's 10 heuristics)

| Heuristic | Assessment | Severity (0–4) left after fixes |
|---|---|---|
| 1. Visibility of system status | Tray icon has four states with text tooltips. `status` prints a one-line summary. Paused state shows the resume time. | 0 |
| 2. Match with the real world | The UI says "Protection on/off", "Ads", "Trackers", "Malware" and never "DNS sinkhole" or "NRPT". Technical words appear only in `doctor` and `--verbose`. | 1 (`why` output must name lists in plain words, for example "HaGeZi Pro (ads list)") |
| 3. User control and freedom | Pause auto-resumes. Allowlist entries are reversible (`unallow`). `harden-browsers --undo`. Uninstall restores the previous state exactly. | 0 |
| 4. Consistency and standards | Verb-first CLI (`adblock allow x`), the same words in the tray and CLI, standard Windows tray behaviour (left-click toggles the menu) | 0 |
| 5. Error prevention | Port pre-check before install. List sanity checks. Critical-domain allowlist. Telemetry and DoH categories are off by default with warnings. | 1 (users can still add over-broad blocks like `block com`, so add a confirmation for TLD-level or very broad entries) |
| 6. Recognition rather than recall | Recently-blocked menu (no need to remember domains), category toggles instead of list URLs | 0 |
| 7. Flexibility and efficiency | CLI for experts, tray for everyone. `--json`, `-f` follow mode, pause durations. | 0 |
| 8. Aesthetic and minimalist design | Tray menu has ≤ 9 items. No dashboard in v1. | 0 |
| 9. Help users recover from errors | `doctor` gives a diagnosis plus the exact fix. Red tray state links to it. Every CLI error says what to do next. | 1 (doctor's coverage needs to grow with real bug reports) |
| 10. Help and documentation | `adblock help <cmd>` with examples, a README with "site is broken?" and "no internet?" sections first | 1 (to write in M6) |

New design change from this pass: **confirm very broad user blocks** (a TLD or a top-1k domain) before applying them. Added to M2 scope.

## 4. Accessibility check

- Tray state is never shown by colour alone: the icon shape changes (check, pause bars, exclamation mark) and the tooltip carries text.
- CLI: respects `NO_COLOR`, has no emoji when output is not a TTY, works with screen readers because output is plain text lines.
- Tray menu items are standard Win32 menus, so they're keyboard and screen-reader accessible for free.

## 5. Predicted SUS score

A design-stage estimate for each persona, using the 10 SUS statements with the fixes in place:

| Persona | Predicted SUS | Main risk to the score |
|---|---|---|
| P1 | ~80 (Good–Excellent) | First-run trust: SmartScreen warning if unsigned, so code signing matters |
| P2 | ~85 | Conflicts with dev tools and VPN; `doctor` quality |
| P3 | ~75 | Lock mode needs admin-account literacy |
