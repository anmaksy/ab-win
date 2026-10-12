# Usability review of the design

**Date:** 2026-10-12
**Scope:** The CLI and tray design in [PLAN.md](PLAN.md), sections 4–6.
**Honesty note:** Sections 1–5 are the **design-stage** review, done before any code existed. Section 6 repeats it on the built app (M4/M6). Both are Claude's own review passes (walkthroughs and heuristics), not studies with real users.

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
| T1 | Install and turn on protection | P1 (a friend) | Download zip → open terminal as admin → `ab-win install` | P1 won't open an admin terminal. "Access denied" is a dead end. The unsigned exe triggers a SmartScreen warning. | **Double-click `ab-win.exe` from GitHub Releases → Install → UAC** (section 5.6). `ab-win install` self-elevates. README screenshot for "More info → Run anyway". | < 60 s |
| T2 | Check that it's working | P1 | `ab-win status` | P1 never opens a terminal | Tray icon colour, **plus** a text tooltip, plus a "Blocked today: N" counter as visible proof of value (section 4.2) | < 5 s |
| T3 | A site is broken, fix it | P1 | `ab-win recent --blocked` → find domain → `ab-win allow x` | Needs DNS knowledge. This is the #1 reason people uninstall ad blockers. | Tray → **Recently blocked → click → Allow** (2 clicks). `ab-win why <domain>` for P2. | < 30 s |
| T4 | Temporarily turn it off | P1/P2 | `ab-win off` | Users forget to turn it back on, so protection silently stays off for weeks | **Pause** with auto-resume is the primary action (5 min / 1 h / until restart). `off` hints at `pause` once. The tray shows an amber "paused" state with the resume time. | < 5 s |
| T5 | Turning off must not break internet | all | Draft: off = restore adapter DNS | Restoring DNS on every toggle is slow and fragile, and a crash midway leaves no DNS | Off and pause **only change the policy**. DNS routing stays on loopback, and only uninstall restores it (section 5.2). | instant |
| T6 | Uninstall cleanly | P1 | Draft: delete the folder | Leaves DNS pointing at a dead loopback, so there's no internet | Uninstalling from Windows "Installed apps" or with `ab-win uninstall` restores DNS. `restore-dns.ps1` is documented as a last resort. The watchdog restores DNS after repeated crashes (section 5.4). | < 60 s |
| T7 | It isn't blocking in Firefox | P2 | No path | Silent failure: Firefox DoH bypasses us | Canary domain by default. `ab-win doctor` explains the cause and offers `harden-browsers` (section 6). | < 2 min |
| T8 | Docker or Hyper-V conflict | P2 | Install fails with "bind: address in use" | Cryptic error | Port-53 pre-check names the conflicting service and suggests a fix (section 5.1) | < 2 min |
| T9 | Stop the kid from turning it off | P3 | No path | Any user can pause it | `lock_settings = true`: the pipe ACL only lets admins toggle. The tray shows "Managed by administrator" instead of greyed-out mystery buttons. | < 2 min |
| T10 | Script it | P2 | Parse text output | Brittle | `--json` on every read command, stable exit codes (section 4.1) | — |

## 3. Heuristic evaluation (Nielsen's 10 heuristics)

| Heuristic | Assessment | Severity (0–4) left after fixes |
|---|---|---|
| 1. Visibility of system status | Tray icon has four states with text tooltips. `status` prints a one-line summary. Paused state shows the resume time. | 0 |
| 2. Match with the real world | The UI says "Protection on/off", "Ads", "Trackers", "Malware" and never "DNS sinkhole" or "NRPT". Technical words appear only in `doctor` and `--verbose`. | 1 (`why` output must name lists in plain words, for example "HaGeZi Pro (ads list)") |
| 3. User control and freedom | Pause auto-resumes. Allowlist entries are reversible (`unallow`). `harden-browsers --undo`. Uninstall restores the previous state exactly. | 0 |
| 4. Consistency and standards | Verb-first CLI (`ab-win allow x`), the same words in the tray and CLI, standard Windows tray behaviour (left-click toggles the menu) | 0 |
| 5. Error prevention | Port pre-check before install. List sanity checks. Critical-domain allowlist. Telemetry and DoH categories are off by default with warnings. | 1 (users can still add over-broad blocks like `block com`, so add a confirmation for TLD-level or very broad entries) |
| 6. Recognition rather than recall | Recently-blocked menu (no need to remember domains), category toggles instead of list URLs | 0 |
| 7. Flexibility and efficiency | CLI for experts, tray for everyone. `--json`, `-f` follow mode, pause durations. | 0 |
| 8. Aesthetic and minimalist design | Tray menu has ≤ 9 items. No dashboard in v1. | 0 |
| 9. Help users recover from errors | `doctor` gives a diagnosis plus the exact fix. Red tray state links to it. Every CLI error says what to do next. | 1 (doctor's coverage needs to grow with real bug reports) |
| 10. Help and documentation | `ab-win help <cmd>` with examples, a README with "site is broken?" and "no internet?" sections first | 1 (to write in M6) |

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

## 6. Built-app review (2026-10-12)

The same walkthrough, re-run against the real binary. The CLI was exercised against a live resolver (`ab-win run`). The tray was smoke-tested and its icons rendered and inspected. The install and uninstall flows were traced through the code, because running them needs admin: they're covered by `tests/service-e2e.ps1` in CI.

| # | Task | What the built app does | Verdict |
|---|---|---|---|
| T1 | Install | Double-click → "Install ab-win?" dialog → UAC → hidden elevated install → tray starts → "Done — protection is on" dialog. The console window is hidden right away. | ✅ Two clicks plus UAC. Remaining friction: SmartScreen (unsigned) and a generic exe icon. |
| T2 | Is it working? | The shield's shape and colour, a tooltip, and "Blocked today: N" in the menu. `ab-win status` prints one line first: `✔ Protected — 4 blocked today (14 lookups)`. | ✅ |
| T3 | Fix a broken site | Tray → Recently blocked → "Allow cdn.example.com" → confirmation ("Reload the page"). CLI: `why` prints the exact `allow` command to run, and `allow` accepts a pasted URL. | ✅ 2 clicks |
| T4 | Turn off briefly | Tray → Pause → 5 min / 1 h / until restart. The header shows "Paused until 14:35". `off` prints the pause tip once. | ✅ |
| T5 | Off can't break internet | Off and pause only switch the policy; adapters are untouched. Verified: toggling never changes DNS. | ✅ |
| T6 | Uninstall | "Installed apps" entry → elevated uninstall → dialog "your original DNS settings are back". | ✅ (end-to-end in CI) |
| T7 | Not blocking in Firefox | `doctor` reads Firefox `prefs.js` and Chromium `Local State` for hand-enabled DoH and points to `harden-browsers`. | ✅ |
| T8 | Port conflict | Install and `doctor` name the process and service holding port 53, with a specific fix for ICS, Docker, AdGuard, dnscrypt, Acrylic and Technitium. Verified with a second instance: "port 53 is already used by ab-win.exe, PID …". | ✅ |
| T9 | Lock for a kid | **Gap found:** the only way in was hand-editing `config.toml` and running `reload`. **Fixed:** added `ab-win lock on\|off`, which self-elevates. Locked trays show "(managed by administrator)" and disable the toggles. | ✅ after fix |
| T10 | Scripting | `--json` on read commands (`recent --json` emits JSON lines), stable exit codes 0/1/2/3, verified. | ✅ |

Issues found and fixed in this pass:

- Plain-text (non-TTY) output labelled every blocked query "Problem:". It now says `BLOCKED` / `ALLOWED`.
- The seed list showed up in `why` as "built-in Ads (includes most trackers) list". It's now "built-in ads list".
- When ab-win wasn't installed, `doctor` flagged each adapter as a failure and told the user to restart a service that doesn't exist. Adapters are now listed as info in that state.
- Memory: the first build used 304 MB after a list update, against an 80 MB target. Compilation now keys on hashes and runs two streaming passes, and it returns memory to Windows afterwards. Measured: 46–57 MB with 2.1M domains.
- Uninstall's process cleanup would have killed the waiting, non-elevated `ab-win.exe`, which meant losing the "done" dialog. It now targets only tray processes.

Still open:

| Item | Severity (0–4) |
|---|---|
| SmartScreen warning on an unsigned exe (first-run trust) | 2: mitigated by the README walkthrough. Code signing is staged (PLAN 5.6). |
| Generic exe icon in Explorer and the download bar | 1 |
| The tray header only refreshes every 3 s after a CLI change | 0 |

