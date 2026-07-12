# archcanary

[![Release](https://img.shields.io/github/v/release/musqz/archcanary?sort=semver)](https://github.com/musqz/archcanary/releases)

> **BETA — actively seeking testing and feedback.** Expect breaking changes, rough edges, and incomplete docs.
> Primarily developed and tested on Mabox Linux (Arch-based, Openbox). Testing on Manjaro and other Arch derivatives is in progress — it should work fine, but rough edges are expected.
> If you run into anything, please open an [issue](https://github.com/musqz/archcanary/issues) or start a [discussion](https://github.com/musqz/archcanary/discussions).

> **Read-only by design.** The scanner detects and reports — it never deletes, quarantines, or disables anything.
> Remediation is left to you. The only writes are its own logs and config lists. `install.sh`, `--refresh`, and the allowlist editors (DKMS, systemd, bpftool) are the exceptions — all explicit.

> **Developed with Claude AI (Anthropic).** All AI-assisted code and documentation is reviewed by the developer before commit. Treat all detections as advisory, not authoritative.

---

## What is archcanary?

archcanary is a layered security detection stack for Arch Linux — scanning for malicious AUR packages, systemd/eBPF persistence, npm/bun cache poisoning, kernel module tampering, library injection, and more.

It started from [lenucksi/aur-malware-check](https://github.com/lenucksi/aur-malware-check) under the name **aur-malware-check**, originally focused on the June 2026 AUR supply-chain attack. 
As the tool grew to cover a much broader set of system checks — integrating a GUI frontend, automated systemd timers, and multiple detection layers — the scope outgrew the original name. 

[aurscan](https://github.com/manticore-projects/aurscan), an LLM-based PKGBUILD scanner, is an optional add-on; archcanary works fully without it. 

---

## Screenshots

<table>
<tr>
<td align="center" width="40%">
<img src="images/gui.png" alt="Archcanary GUI — main menu" width="320"/><br/>
<sub>Main menu — all checks passed</sub>
</td>
</tr>
</table>

---

## Projects Used

archcanary integrates with and builds on the following — see
[docs/my-setup.md § Components](docs/my-setup.md#components) for what each one
does and how it's wired in:

| Project | Required |
|---------|----------|
| [manticore-projects/aurscan](https://github.com/manticore-projects/aurscan) | Optional |
| [traur](https://aur.archlinux.org/packages/traur) | Optional |
| [yay](https://github.com/Jguer/yay) 13.0 | Optional |
| [yad](https://github.com/v1cont/yad) | GUI only |
| [bpftool](https://github.com/libbpf/bpftool) (pkg: `bpf`) | Optional (`--check-bpftool`) |
| [libnotify](https://gitlab.gnome.org/GNOME/libnotify) | Optional |
| [polkit](https://gitlab.freedesktop.org/polkit/polkit) / pkexec | GUI + `--system` install |
| [lynis](https://cisofy.com/lynis/) | Optional |
| [audit](https://people.redhat.com/sgrubb/audit/) / auditd | Optional |

Started from [lenucksi/aur-malware-check](https://github.com/lenucksi/aur-malware-check) — see [Attribution](#attribution) below.

### Detection Layers

Four automatic layers fire at AUR install time — yay's editor-gate
(aurscan + Claude), yay's offline `init.lua` hooks, and traur's pacman
`PreTransaction` hook — plus a continuous root scan (`archcanary --full`,
weekly + on boot + after every pacman transaction), a desktop notifier on
detection, and the on-demand GUI.

See [docs/overview.md](docs/overview.md) for the full lifecycle diagram
(at-a-glance table included).

---

## Quick Start

```bash
# Check if you installed any compromised packages
archcanary

# Full scan — all checks (some require root)
sudo archcanary --full

# Check setup health
archcanary --doctor

# Refresh package list from the live HedgeDoc, then scan
archcanary --refresh --full

# GUI frontend (requires yad)
archcanary-gui

# Full scan in terminal — no GUI, structured summary output
archcanary-gui --no-gui
```

Every scan prints a per-check summary before the final verdict:

```
 Check summary
 ───────────────────────────────────────────────────────
 Package list (1943 pkgs)            ✅  clean
 pacman.log history                  ✅  clean
 Systemd persistence                 ✅  clean
 eBPF rootkit traces                 ✅  clean
 npm cache                           ✅  clean
 bun cache                           ✅  clean
 yarn cache                          ✅  clean
 pnpm cache                          ✅  clean
 PKGBUILD obfuscation scan           ✅  clean
 eBPF programs (bpftool)             ⚠   skipped (needs root)
 ld.so.preload injection             ✅  clean
 XDG autostart + shell RCs           ✅  clean
 Kernel modules (DKMS)               ⚠   skipped (needs root)
 ───────────────────────────────────────────────────────
============================================================
 RESULT: CLEAN - No indicators found.
============================================================
```

---

## Checks

| Flag | What it does | Root? |
|------|-------------|-------|
| *(default)* | Package list match against installed AUR packages | No |
| `--check-systemd` | Systemd persistence: unknown services, drop-ins, Restart= timers | No |
| `--check-ebpf` | eBPF rootkit traces (`/sys/fs/bpf/hidden_*`) | No |
| `--check-npm-cache` | npm cache for malicious package names | No |
| `--check-bun-cache` | bun cache for malicious package names | No |
| `--check-yarn-cache` | yarn cache scan | No |
| `--check-pnpm-cache` | pnpm cache + fnm per-version Node installs | No |
| `--check-pkgbuild` | AUR helper cache — obfuscation patterns (base64, eval, var-split, printf hex, ANSI-C hex/octal, rev/tr pipe-to-shell) | No |
| `--check-bpftool` | Enumerate loaded eBPF programs (stealth types), perf/kprobe attachments with owning PID and hooked function, XDP/TC network attachments | Yes |
| `--check-ldso` | `/etc/ld.so.preload` injection + recent `/etc/ld.so.conf.d/` changes | No |
| `--check-autostart` | `~/.config/autostart`, user systemd services, shell RC download-and-exec patterns | No |
| `--check-kmod` | Kernel modules not owned by pacman; untracked DKMS builds | Yes |
| `--check-lynis` | Read last Lynis report — hardening index, warnings, scan date | Yes |
| `--run-lynis` | Run `lynis audit system`, stream output | Yes |
| `--check-pkginteg` | Verify installed file checksums via `pacman -Qkk`. Reports SHA256 mismatches on non-backup, non-factory files. Backup files (pacman-managed configs expected to diverge) and `/factory/` paths are filtered out. Prioritise hits in `/usr/bin/`, `/usr/lib/`, `/usr/sbin/`. | Yes |
| `--full` | All of the above | Partial |
| `--refresh` | Fetch the live package list from the Arch Linux HedgeDoc | — |
| `--package-list=PATH` | Override the infected AUR package list | — |
| `--extra-list=PATH_OR_URL` | Load an additional package list (file or `https://` URL); repeatable | — |
| `--doctor` | Health check: binary deps, systemd units, install paths | — |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean — no indicators found |
| 1 | Warnings (log scan issues, missing files) |
| 2 | Infected packages or artifacts detected |

---

## Installation

```bash
# User install — scripts, config seeding, desktop entry
./install.sh

# System install — adds root helper, polkit policy, systemd automated scan
./install.sh --system

# Uninstall
./install.sh uninstall --system
```

`--system` sets up:
- Root system timer: weekly + on boot + after each pacman transaction
- User notifier: watches `/var/lib/archcanary/last-scan.log`, fires a desktop alert on `INFECTED`
- pkexec root helper for GUI-triggered root checks (eBPF, bpftool, kmod, Lynis)
- auditd ruleset at `/etc/audit/rules.d/30-archcanary.rules` when auditd is installed (seeded from template, editable via GUI)

See [docs/systemd.md](docs/systemd.md) for unit file details and [docs/my-setup.md](docs/my-setup.md) for the full personal stack and reinstall steps.

---

## LLM Settings (aurscan)

[aurscan](https://github.com/manticore-projects/aurscan) scans PKGBUILDs with an LLM before `yay` or `paru` builds them. The GUI exposes its backend configuration under **Settings → LLM settings**.

Install from the AUR:

```bash
yay -S aurscan-manticore-git
```

> **AUR helper compatibility:** aurscan integrates natively with both **yay** and **paru** — one-time setup, no wrapper alias needed. yay uses its Lua editor-gate (`aurscan --install-yay-hook`); paru uses its native `PreBuildCommand` config key (`aurscan --install-paru-hook`), which paru invokes in the PKGBUILD directory before every build. Other helpers (pikaur, aurutils) have no equivalent hook yet. archcanary's post-install detection (all other checks) works with any AUR helper.

<img src="images/llm.png" alt="LLM Settings dialog" width="400"/>

| Field | Description |
|-------|-------------|
| Backend | `auto` — Claude if `ANTHROPIC_API_KEY` is set, else static rules only<br>`claude` — Claude API<br>`openai` — any OpenAI-compatible endpoint (Ollama, llama.cpp, vLLM) |
| Endpoint URL | URL for the `openai` backend, e.g. `http://localhost:11434/v1` |
| Fallback URL | Optional second endpoint — aurscan fails over automatically |
| Model | Model name sent to the endpoint |
| Timeout | Per-request budget in seconds — raise for slow CPU-only local models (default 180 s) |

Settings are saved to `~/.config/aurscan/env` and loaded by aurscan at startup. Explicit environment variables always override the file.

The **Model guide** button in the dialog shows local model size recommendations and the critical Ollama `num_ctx` warning (Ollama defaults to 2048 which silently truncates the PKGBUILD — set ≥ 8192).

---

## Campaigns Detected

### JS Supply-Chain Attack (June 9–12, 2026)

Attackers used commit forgery to impersonate AUR maintainers, injecting malicious `npm`/`bun` install hooks into 1600+ package PKGBUILDs. Payload: an infostealer and eBPF rootkit.

**What it steals:** Discord tokens, GitHub PATs, npm/Slack/Teams sessions, SSH keys, Vault tokens, Docker credentials, browser cookies — exfiltrated via `temp.sh` and a Tor C2.

**Persistence:** systemd services with `Restart=always`; eBPF rootkit hides processes, files, and socket inodes when run as root with CAP_BPF.

Three waves:
- **Wave 1 (npm)** — `atomic-lockfile` / `lockfile-js`; accounts `krisztinavarga`, `franziskaweber`, `tobiaswesterburg`, `ellenmyklebust`. Note: `arojas` was impersonated via git commit forgery — he is a legitimate KDE maintainer ([clarification](https://chaos.social/@dvzrv/116736017948300691)).
- **Wave 2 (bun)** — `js-digest`; accounts `custodiatovar`, `veramagalhaes`.
- **Wave 3 (obfuscated bun)** — June 14, 2026; Node.js packages, Plasma 6 applets, Firefox packages, Aura browser, LibreWolf extensions, NeoVim plug-ins. More elaborate obfuscation around the `bun` command; discovered by a821 and Nicolas Boichat (using a local Gemma E2B AI model). ([Phoronix](https://www.phoronix.com/news/Arch-Linux-AUR-More-Malware))

### Russian Spam Campaign (June 14, 2026)

A separate campaign ([reported by Sid Karunaratne](https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/message/2YQSHTC27MOKDDKHZTH2BJGTEN2CYC7W/)) in which 73 AUR package PKGBUILDs were modified to inject Russian-language spam `echo` statements into `~/.bashrc`, `~/.zshrc`, and other shell configs at install time. No credential theft or persistence — nuisance/propaganda payload. Reported to Arch DevOps; cleanup was in progress as of 2026-06-14.

archcanary detects these via `malicious_russian_spam_packages.txt` (shown in the scan header alongside the JS campaign count).

---

## What to Do If Infected

1. **Preserve the system** — do not power off; use forensic acquisition from trusted media
2. **Rotate all credentials** — Discord, GitHub, npm, Slack, Teams, SSH keys, Vault tokens, cloud keys
3. **Check for persistence** — `systemctl list-units --type=service --state=running`; run `--check-systemd`
4. **Check for eBPF rootkit** — `ls -la /sys/fs/bpf/hidden_*`; run `sudo archcanary --check-bpftool`
5. **Check for library injection** — `cat /etc/ld.so.preload`; run `archcanary --check-ldso`
6. **Check for user-space persistence** — run `archcanary --check-autostart`
7. **Check for rogue kernel modules** — run `sudo archcanary --check-kmod`
8. **Clean from trusted media** — boot from Arch ISO, mount filesystem, remove malicious units
9. **Consider reinstallation** — the rootkit makes the system untrustworthy once active
10. **Report** — https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/

---

## Documentation

- [docs/overview.md](docs/overview.md) — lifecycle diagram, at-a-glance table
- [docs/systemd.md](docs/systemd.md) — systemd unit files and automated scan setup
- [docs/my-setup.md](docs/my-setup.md) — full personal stack, component connections, reinstall steps
- [docs/false-positives.md](docs/false-positives.md) — documented benign signals and how to verify
- [SOURCES.md](SOURCES.md) — full numbered source references

---

## Attribution

Community detection scripts this consolidates:

| Author | Contribution |
|--------|-------------|
| [Kidev](https://gist.github.com/Kidev/59bf9f5fb53ab5eee99f19a6a2fc3992) | Original foundation: package list (~446 entries), basic `pacman -Qi` loop |
| [BrianCArnold](https://gist.github.com/BrianCArnold/beb514ffc95a9a251b0dc2f767471fca) | Efficiency: `pacman -Qm` piped through grep |
| [commonsourcecs](https://cscs.pastes.sh/aurvulntest20260611.sh) | Batch `pacman -Qmq`, date window filtering, expanded list |
| [Kacper-Kondracki](https://gist.github.com/Kacper-Kondracki/88c5b313f79cc1f9c347e7ed61a36d10) | `pacman.log` historical scanning, compressed log support, configurable date window |
| [quantenProjects](https://gist.github.com/quantenProjects/3f768dce7331618310f016d975bf8547) | Safe `comm -1 -2` one-liner approach |
| drbbgh (upstream PR #8) | `--refresh` flag — live package list from Arch Linux HedgeDoc |
| liphiwolf (upstream PR #7) | `lockfile-js` detection, expanded package list |

Full source list with URLs: [SOURCES.md](SOURCES.md).

---

## License

Community tools — no warranty. Use at your own risk.
