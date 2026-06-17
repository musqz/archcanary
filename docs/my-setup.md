# Personal setup — Mabox Linux

Full overview of how this fork is deployed and how the pieces connect.

## Components

| Component | Package / Source | Purpose |
|-----------|-----------------|---------|
| `aur_check-v2.sh` | [musqz/aur-malware-check](https://github.com/musqz/aur-malware-check) (fork of [lenucksi/aur-malware-check](https://github.com/lenucksi/aur-malware-check)) | Main scanner — known-bad packages, pacman logs, systemd persistence (incl. drop-ins + timers), eBPF rootkit, npm/bun/yarn/pnpm cache, PKGBUILD obfuscation (incl. base64/eval/printf/varsplit), loaded-eBPF enumeration (`bpftool`), `ld.so.preload` injection, XDG autostart + shell RC persistence, kernel module / DKMS audit |
| `aur_malware_gui.sh` | [musqz/aur-malware-check](https://github.com/musqz/aur-malware-check) | yad GUI — grouped menu with per-session status column (✅/⚠/❌/?), polkit auth for root checks, streaming output window |
| `traur` | [AUR: traur](https://aur.archlinux.org/packages/traur) | Pre-install trust scanner — 279 signals across PKGBUILD static analysis (reverse shells, download-and-execute, obfuscation, exfiltration), maintainer behaviour (new account, orphan takeover, typosquatting), AUR metadata (votes, popularity, orphaned), and git history (major rewrites, checksum removal, source domain changes) |
| `aurscan` | [manticore-projects/aurscan](https://github.com/manticore-projects/aurscan) | LLM-based pre-install PKGBUILD scanner using Claude — proactive check before installing an AUR package |
| `yad` | official repos | GTK dialog toolkit used by `aur_malware_gui.sh` |
| `polkit` / `pkexec` | official repos | Graphical privilege escalation for root-requiring checks (eBPF, kmod) in the GUI |
| `libnotify` | official repos | Provides `notify-send` — the desktop notification on exit code 2 |
| `bpftool` | `bpf` — official repos | Enumerates loaded eBPF programs for `--check-bpftool` |

## How the pieces connect

```
systemd timer (weekly + on boot)
    └── aur_check-v2.sh --refresh --full --all-time
            ├── [1]  currently installed foreign packages
            ├── [2]  historical pacman logs
            ├── [3]  systemd persistence (services, drop-ins, timers)
            ├── [4]  eBPF rootkit traces (/sys/fs/bpf/hidden_*)
            ├── [5]  npm cache
            ├── [6]  bun cache
            ├── [6b] yarn cache
            ├── [6c] pnpm cache
            ├── [7]  PKGBUILD / install file scan (obfuscation-aware)
            ├── [8]  loaded eBPF programs via bpftool (stealth hook types)
            ├── [9]  ld.so.preload injection
            ├── [10] XDG autostart + shell RC persistence
            └── [11] kernel module / DKMS audit (needs root)
                    │
                    └── exit code 2 (infected)?
                            └── notify-send (libnotify) → critical desktop alert
                                    └── open AUR Malware Check from the app launcher to review

aur_malware_gui.sh (on-demand — desktop shortcut or app launcher)
    └── yad list menu with per-session status column
            ├── standard checks run as user
            └── root checks (eBPF, bpftool, kmod) → pkexec → polkit auth → root-helper
                    └── streams output live, updates status on close

traur — two use cases:
    ├── GUI "Trust scan (traur)"  → traur scan  (no args)
    │       └── bulk audit of ALL installed AUR packages
    │               └── useful as a periodic sweep alongside aur_check-v2.sh
    │
    └── terminal: traur scan <pkg>  (before installing a specific package)
            └── 279 signals, 5 weighted categories
                    ├── Pkgbuild (0.45)   — static analysis: shells, download-exec, obfuscation, exfil, miners
                    ├── Behavioral (0.25) — maintainer: new account, batch creation, orphan takeover, typosquat
                    ├── Metadata (0.15)   — AUR page: votes, popularity, orphaned, flagged, missing URL
                    ├── Temporal (0.15)   — git history: single commit, major rewrite, domain change, checksum drop
                    └── Safety analysis   — char-by-char construction, high-entropy heredocs, indirect exec
                            └── trust score + per-signal breakdown
    note: pre-install scan of a specific package requires the terminal —
          the GUI has no package name input

aurscan (manual — before installing any AUR package)
    └── scans PKGBUILD with Claude LLM before yay installs it
```

### Scanner comparison

| Tool | When | How | Catches |
|------|------|-----|---------|
| `traur scan <pkg>` | Before install (terminal) | 279 heuristic signals | Unknown suspicious packages |
| `traur scan` (GUI) | On demand — periodic audit | Same signals, all installed AUR pkgs | Suspicious packages already on system |
| `aurscan` | Before install (terminal) | LLM reads PKGBUILD | Novel / obfuscated patterns |
| `aur_check-v2.sh` | After install (automated) | IOC list matching | Known-compromised packages |

All are complementary — none replaces the others.

### The yad GUI (`aur_malware_gui.sh`)

Run from a desktop shortcut or app launcher — grouped menu with a per-session status column, polkit auth for root-requiring checks, and a live streaming output window:

![aur_malware_gui.sh yad GUI — status column and grouped checks](../images/gui.png)

### Headless / SSH

There is no separate terminal menu. Over SSH or on a display-less box, run the scanner directly:

```bash
aur-malware-check.sh --full --all-time                # everything
aur-malware-check.sh --check-systemd                  # a single check
sudo ~/.local/bin/aur-malware-check.sh --check-kmod   # root-requiring check
```

> The root check uses the **full path** under `sudo`. `sudo` resets `$PATH` to its
> `secure_path` (set in `/etc/sudoers`), which does not include `~/.local/bin`, so a
> bare `sudo aur-malware-check.sh` fails with *command not found*. The script then
> resolves your config from `$SUDO_USER`, so the lists are still found.

The GUI is for interactive desktop use; the CLI covers everything else (SSH, cron, systemd, scripting).

## When each tool runs

| Tool | When | Trigger |
|------|------|---------|
| `aur_check-v2.sh` | Weekly + on boot (catches missed runs) | systemd timer with `Persistent=true` |
| `aur_malware_gui.sh` | On demand | Desktop shortcut / app launcher |
| `aur-malware-check.sh` | On demand (SSH / no display) | Run directly with `--full` or a single `--check-*` flag |
| `traur` | Before each AUR install | Manual — check maintainer reputation |
| `aurscan` | Before each AUR install | Manual — run before `yay -S <pkg>` |

## Install locations

```
~/.local/bin/aur-malware-check.sh     # main script
~/.local/bin/aur_malware_gui.sh       # yad GUI script

~/.config/aur-malware-check/
    ├── package_list.txt              # refreshed weekly via --refresh
    ├── malicious_npm_packages.txt    # static list, auto-seeded on first run
    └── dkms_allowlist.conf           # DKMS modules to skip in --check-kmod

~/.config/systemd/user/
    ├── aur-malware-check.service
    └── aur-malware-check.timer

# system components — installed by ./install.sh --system (requires sudo)
/usr/lib/aur-malware-check/
    ├── aur-malware-check.sh          # root-accessible copy of the main script
    └── root-helper                   # pkexec target (validates flags, restores XDG env)
/usr/share/polkit-1/actions/
    └── org.aur-malware-check.policy  # polkit policy allowing GUI to call root-helper
```

## Dependencies

```bash
# Official repos
# bpf provides bpftool (--check-bpftool); yad is the GUI toolkit;
# libnotify provides notify-send for the desktop alert
sudo pacman -S libnotify bpf yad polkit

# AUR
yay -S traur

# aurscan — GitHub only, no AUR package
# clone from https://github.com/manticore-projects/aurscan and follow its README
```

## Known false positives

See [false-positives.md](false-positives.md) for documented signals that fire on benign packages and how to verify them.

## Systemd unit files

See [systemd.md](systemd.md) for the full service and timer contents.

## Reinstalling from scratch

```bash
# 1. Clone the fork
git clone https://github.com/musqz/aur-malware-check.git ~/Github/aur-malware-check

# 2. Install dependencies (bpf provides bpftool for --check-bpftool; yad for GUI)
sudo pacman -S libnotify bpf yad polkit
yay -S traur

# aurscan — GitHub only, no AUR package
git clone https://github.com/manticore-projects/aurscan.git
# see its README for install instructions

# 3. Run install script (installs to ~/.local/bin by default)
bash ~/Github/aur-malware-check/install.sh

# Also install root helper + polkit policy (enables eBPF/kmod checks in the GUI)
bash ~/Github/aur-malware-check/install.sh --system

# 4. Run a first scan with package list refresh
aur-malware-check.sh --refresh --full --all-time
```
