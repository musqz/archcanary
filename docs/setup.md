# Personal setup — Mabox Linux

Full overview of how this fork is deployed and how the pieces connect.

## Components

| Component | Package / Source | Purpose |
|-----------|-----------------|---------|
| `aur_check-v2.sh` | [musqz/aur-malware-check](https://github.com/musqz/aur-malware-check) (fork of [lenucksi/aur-malware-check](https://github.com/lenucksi/aur-malware-check)) | Main scanner — known-bad packages, pacman logs, systemd persistence, eBPF rootkit, npm/bun cache, PKGBUILD obfuscation |
| `aur_malware_menu.sh` | [musqz/aur-malware-check](https://github.com/musqz/aur-malware-check) | fzf TUI menu — run individual checks or view last log from the notification |
| `aurscan` | [manticore-projects/aurscan](https://github.com/manticore-projects/aurscan) (GitHub only) | LLM-based pre-install PKGBUILD scanner using Claude — proactive check before installing an AUR package |
| `notify-send.sh` | [vlevit/notify-send.sh](https://github.com/vlevit/notify-send.sh) — [AUR: notify-send.sh](https://aur.archlinux.org/packages/notify-send.sh) | Drop-in replacement for `notify-send` with action button support — enables the **Show Menu** button on the alert |
| `fzf` | [junegunn/fzf](https://github.com/junegunn/fzf) — official repos | Menu picker used by `aur_malware_menu.sh` |
| `libnotify` | official repos | Fallback notification backend when `notify-send.sh` is not installed |
| terminal emulator | your preferred terminal | Opened by the **Show Menu** button — auto-detected via `$TERMINAL`, or falls back to `kitty` → `alacritty` → `xterm` → `gnome-terminal` → `xfce4-terminal` |

## How the pieces connect

```
systemd timer (weekly + on boot)
    └── aur_check-v2.sh --refresh --full --all-time
            ├── [1] currently installed foreign packages
            ├── [2] historical pacman logs
            ├── [3] systemd persistence artifacts
            ├── [4] eBPF rootkit traces
            ├── [5] npm cache
            ├── [6] bun cache
            └── [7] PKGBUILD / install file scan (obfuscation-aware)
                    │
                    └── exit code 2 (infected)?
                            └── notify-send.sh → critical alert + [Show Menu] button
                                    └── terminator opens aur_malware_menu.sh
                                            └── fzf menu: pick a check or view log
                                                    └── returns to menu after each run

aurscan (manual — before installing any AUR package)
    └── scans PKGBUILD with Claude LLM before yay installs it
```

## When each tool runs

| Tool | When | Trigger |
|------|------|---------|
| `aur_check-v2.sh` | Weekly + on boot (catches missed runs) | systemd timer with `Persistent=true` |
| `aur_malware_menu.sh` | On demand | **Show Menu** notification button or directly from terminal |
| `aurscan` | Before each AUR install | Manual — run before `yay -S <pkg>` |

## Install locations

```
~/.local/bin/aur-malware-check.sh     # main script
~/.local/bin/aur_malware_menu.sh      # fzf menu script

~/.config/aur-malware-check/
    ├── package_list.txt              # refreshed weekly via --refresh
    └── malicious_npm_packages.txt    # static list, auto-seeded on first run

~/.config/systemd/user/
    ├── aur-malware-check.service
    └── aur-malware-check.timer
```

## Dependencies

```bash
# Official repos (terminator is personal preference — any terminal works)
sudo pacman -S fzf libnotify

# AUR
yay -S notify-send.sh

# aurscan — GitHub only, no AUR package
# clone from https://github.com/manticore-projects/aurscan and follow its README
```

## Systemd unit files

See [systemd.md](systemd.md) for the full service and timer contents.

## Reinstalling from scratch

```bash
# 1. Clone the fork
git clone https://github.com/musqz/aur-malware-check.git ~/Github/aur-malware-check

# 2. Install dependencies
sudo pacman -S fzf libnotify
yay -S notify-send.sh

# aurscan — GitHub only, no AUR package
git clone https://github.com/manticore-projects/aurscan.git
# see its README for install instructions

# 3. Run install script (auto-detects ~/.local/bin or ~/bin from PATH)
bash ~/Github/aur-malware-check/install.sh

# To use ~/bin explicitly:
# bash ~/Github/aur-malware-check/install.sh ~/bin

# 4. Install systemd units (see systemd.md for file contents)
mkdir -p ~/.config/systemd/user
# create service and timer files as documented in systemd.md
systemctl --user daemon-reload
systemctl --user enable --now aur-malware-check.timer

# 5. Run a first scan with package list refresh
aur-malware-check.sh --refresh --full --all-time
```
