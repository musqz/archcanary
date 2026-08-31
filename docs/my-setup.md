# Personal setup — Mabox Linux

Full overview of how this tool is deployed and how the pieces connect.

> For a one-screen visual map (lifecycle diagram + at-a-glance table) start with
> [overview.md](overview.md). This page is the deep reference.

## Components

| Component | Package / Source | Purpose |
|-----------|-----------------|---------|
| `archcanary` | [musqz/archcanary](https://github.com/musqz/archcanary) (started from [lenucksi/aur-malware-check](https://github.com/lenucksi/aur-malware-check)) | Main scanner — known-bad packages, pacman logs, systemd persistence (incl. drop-ins + timers), eBPF rootkit, npm/bun/yarn/pnpm cache, PKGBUILD obfuscation (incl. base64/eval/printf/varsplit), loaded-eBPF enumeration (`bpftool`), `ld.so.preload` injection, XDG autostart + shell RC persistence, kernel module / DKMS audit. Prints a per-check summary table at the end of every scan. |
| `yay` 13.0 `init.lua` | `~/.config/yay/init.lua` | yay 13.0 Lua hooks — an offline layer that runs on every build: upgrade-age warning (`UpgradeSelect`), malicious-pattern block (`AURPostDownload`), and AUR install logging (`PostInstall`) |
| `polkit` / `pkexec` | official repos | Privilege escalation for root-only remediation commands (allowlist edits, audit-rules/lynis-config writes) via `lib/archcanary-root-helper` |
| `libnotify` | official repos | Provides `notify-send` — the desktop notification on exit code 2 |
| `bpftool` | `bpf` — official repos | Enumerates loaded eBPF programs for `--check-bpftool` |
| `lynis` | official repos | System hardening auditor; archcanary reads the last report and can trigger a new audit (`--run-lynis`) |
| `audit` / auditd | official repos | Kernel audit daemon; archcanary ships a default ruleset covering AUR builds, privilege escalation, and system config changes; editable via `--audit-rules-get`/`--audit-rules-set` |

## How the pieces connect

```
systemd SYSTEM timer (weekly + on boot, runs as root)
    └── archcanary --refresh --full --no-notify
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
            └── [11] kernel module / DKMS audit          (root → actually runs)
                    │
                    └── writes /var/lib/archcanary/last-scan.log
                            │
   systemd USER path unit watches that file
            └── on "RESULT: INFECTED" → notify-send (libnotify) → critical desktop alert
                    └── review last-scan.log (or: sudo archcanary --full)

yay install/upgrade  (yay -S <pkg>, yay -Syu, bare yay <term>)  — transparent, no alias
    └── yay init.lua hooks fire on every build
            — see "yay 13.0 integration" below for the full breakdown
```

### Scanner comparison

For the lifecycle map and the what-runs-when table, see
[overview.md](overview.md). All layers are complementary — none replaces the
others.

### Headless / SSH

Run the scanner directly:

```bash
# Full scan — run with sudo for the full picture. Three checks (kmod, ebpf,
# bpftool) need root; without it they are skipped and the run is reported as
# INCOMPLETE (exit 1, WARNINGS) rather than CLEAN, so a partial scan is never
# mistaken for an all-clear.
sudo archcanary --full

# User-level checks run fine without root:
archcanary --check-systemd
archcanary --check-pkgbuild

# A single root-requiring check:
sudo archcanary --check-kmod

# Setup health check — is every element installed and configured? (no root,
# no scan; auto-detects distro/AUR helpers and prints a fix command per gap).
# When something is missing it points to the next step to run.
archcanary --doctor

# Check one section (with extra detail), or several — runs in install order:
# platform, deps, user, system, systemd, external
archcanary --doctor=deps
archcanary --doctor=user,system
```

> With `--system`, the binary lives at `/usr/local/bin/archcanary`, which is on
> sudo's default PATH — bare `sudo archcanary` just works, resolving your
> config from `$SUDO_USER`. A plain (non-`--system`) install puts it in
> `~/.local/bin` instead, which typically isn't on sudo's `secure_path`, so
> that setup needs the full path: `sudo ~/.local/bin/archcanary --full`.

## When each tool runs

See the at-a-glance table in [overview.md](overview.md). The exact systemd
triggers (timer + `.path` units) are in [systemd.md](systemd.md).

## Install locations

```
/usr/local/bin/archcanary        # main script (--system; plain install uses ~/.local/bin instead)

~/.config/archcanary/
    ├── package_list.txt                   # refreshed weekly via --refresh
    ├── malicious_npm_packages.txt         # static lists, auto-seeded on first run
    ├── chaos_rat_packages.txt
    ├── malicious_russian_spam_packages.txt
    ├── aur_audit_black.txt                # synced via --refresh only (no bundled fallback —
    ├── aur_audit_red.txt                  #   third-party live feed, not ours to snapshot)
    └── extra_lists.conf                   # optional extra list subscriptions (paths/URLs)

~/.config/yay/
    └── init.lua                      # Lua hooks (age warning, pattern block, install log) — new in yay 13.0

~/.config/systemd/user/                   # installed by ./install.sh --system
    ├── archcanary-user.service    # user-level scan (npm/bun/pkgbuild caches, autostart)
    ├── archcanary-user.timer      # weekly + on boot
    ├── archcanary-notify.path     # watches the root scan's result file
    └── archcanary-notify.service  # greps INFECTED → notify-send

# system components — installed by ./install.sh --system (requires sudo)
/usr/lib/archcanary/
    ├── archcanary.sh          # root-accessible copy of the main script
    ├── package_list.txt              # bundled lists, seeded so the root scan finds them
    ├── malicious_npm_packages.txt
    ├── chaos_rat_packages.txt
    ├── malicious_russian_spam_packages.txt
    └── root-helper                   # pkexec target (validates flags, restores XDG env)
/etc/archcanary/
    ├── dkms_allowlist.conf           # DKMS allowlist
    ├── systemd_allowlist.conf        # systemd unit allowlist
    ├── bpftool_allowlist.conf        # bpftool eBPF loader allowlist
    └── autostart_allowlist.conf      # XDG autostart Exec= allowlist
                                       # (all four: sudoedit directly, or --allowlist-add/--allowlist-remove)
/usr/share/polkit-1/actions/
    └── org.archcanary.policy  # polkit policy authorizing root-helper via pkexec

# automated scan — units installed by ./install.sh --system
/etc/systemd/system/
    ├── archcanary.service     # system-level scan as root, writes last-scan.log
    ├── archcanary.timer       # weekly + on boot
    ├── archcanary-onchange.service
    ├── archcanary.path        # triggers after each pacman transaction
    ├── archcanary-scan-all-homes.service  # opt-in: sudo -u per real local user
    └── archcanary-scan-all-homes.timer    # weekly, disabled by default
/var/lib/archcanary/
    ├── last-scan.log                 # shared result the user notifier watches
    └── last-scan-all-homes.log       # scan-all-homes result (if enabled)
```

## Dependencies

```bash
# Official repos
# bpf provides bpftool (--check-bpftool); libnotify provides notify-send
# for the desktop alert; polkit provides pkexec for privileged remediation
sudo pacman -S libnotify bpf polkit
```

## yay 13.0 integration

The yay 13.0 Lua hooks (`~/.config/yay/init.lua`) — **never installed automatically**, by either the AUR package or `install.sh`: it's a per-user path no install path can reach, and the hook is opt-in regardless. Copy the template in yourself:

```bash
# from a git clone
cp configs/yay-init.lua ~/.config/yay/init.lua

# from the AUR package
cp /usr/lib/archcanary/yay-init.lua ~/.config/yay/init.lua
```

`archcanary --doctor` prints the exact command for your install (source: [`configs/yay-init.lua`](../configs/yay-init.lua)). Re-copy it by hand (merging in any of your own customizations) whenever `--doctor` flags your copy as outdated — nothing ever overwrites an existing `init.lua` for you, whether it's an older archcanary copy or hooks you wrote yourself. An offline backstop that fires on every AUR build:

| Hook | Event | What it does |
|------|-------|--------------|
| Upgrade-age warning | `UpgradeSelect` | Warns for any AUR upgrade whose PKGBUILD was modified < 3 days ago (prints hours since change) — a freshly rewritten PKGBUILD is the classic compromise signal |
| Pattern block + aur-audit check | `AURPostDownload` | One combined hook, runs after yay's own diff/edit/clean review menus and `makepkg --verifysource` (so it sees the PKGBUILD as reviewed, not a stale pre-review copy): aborts if the PKGBUILD matches a known-malicious pattern (`npm install atomic-lockfile`, `bun install js-digest`, `curl`/`wget` piped to `bash`/`sh`, `eval`+subshell, `printf` hex/octal obfuscation, variable-split command reassembly, base64-decode piped to a shell, chained ANSI-C hex/octal escapes (3+), or `rev`/`tr` piped to a shell — a Lua port of most of `check_pkgbuild_caches`' bash detections; the ELF-binary-in-git-tree check has no Lua equivalent, since it needs filesystem/git access rather than just the PKGBUILD text), **warns** (doesn't block) on `sudo`/`doas`/`pkexec` invoked from a PKGBUILD `build()`/`package()` (not `sudo -u <user>`, which is de-escalation) or on an unchecksummed `source=` entry pointing at a mutable merge-request/pull-request diff, and aborts/warns on a black/red hit from the [aur-audit.wtako.net](https://wtako.net/services/aur-audit) feed synced by `--refresh`. Prints `ARCHCANARY: <pkg> — PKGBUILD CHECKS CLEAN!` when nothing fires — an explicit clean line, since otherwise silence is indistinguishable from the hook never having run at all. On any non-aborted outcome (clean, or a warning), blocks with `read` on a "press Enter to continue" prompt (skipped when stdin isn't a terminal) so the verdict is a checkpoint you have to acknowledge, not a line that scrolls away under makepkg/cargo build spam |
| Install log | `PostInstall` | Logs every installed AUR package (name + version) via `yay.log.info` |

Options set in `init.lua`: `diff_menu = true`, `clean_menu = true`, `sort_by = "votes"`, and `edit_menu = true` (lets you review each PKGBUILD's diff before it builds).

Using paru instead of yay? See [paru integration](paru-integration.md) for the equivalent hook.

## Shell completion

Both install paths (`install.sh` and the AUR package) drop a bash-completion script into `/usr/share/bash-completion/completions/archcanary` (system) or `~/.local/share/bash-completion/completions/archcanary` (user) — loads automatically via the `bash-completion` package, no `.bashrc` edits required. `archcanary --<TAB>` lists every flag; `--doctor=<TAB>`, `--color=<TAB>`, and the `--*-list=<TAB>`/`--log-file=<TAB>` flags complete their values (section names, `auto|always|never`, and file paths respectively).

## Systemd unit files

See [systemd.md](systemd.md) for the full service and timer contents.

## Reinstalling from scratch

```bash
# 1. Clone the fork
git clone https://github.com/musqz/archcanary.git ~/Github/archcanary

# 2. Install dependencies (bpf provides bpftool for --check-bpftool)
sudo pacman -S libnotify bpf polkit

# 3. Run install script (installs to ~/.local/bin by default)
bash ~/Github/archcanary/install.sh

# Also install root helper + polkit policy (enables eBPF/kmod checks +
# pkexec-based remediation commands)
bash ~/Github/archcanary/install.sh --system

# 4. Run a first scan with package list refresh
archcanary --refresh --full
```
