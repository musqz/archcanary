# Running aur-malware-check via systemd

Run the scanner automatically on login or on a timer, and get a desktop notification if anything is found.

## User service + timer (recommended)

Create two files under `~/.config/systemd/user/`:

**`~/.config/systemd/user/aur-malware-check.service`**
```ini
[Unit]
Description=AUR malware check
After=network.target

[Service]
Type=oneshot
ExecStart=%h/.local/bin/aur-malware-check.sh --refresh --full --all-time --log-file=%h/.config/aur-malware-check/last-scan.log
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aur-malware-check
```

> `--log-file=` is set to a fixed path so the scan overwrites one log instead of dropping a timestamped `aur-check-<date>.log` in the service's working directory (`$HOME` for user units) on every run. Full output is also in the journal.

**`~/.config/systemd/user/aur-malware-check.timer`**
```ini
[Unit]
Description=Run AUR malware check weekly and on boot

[Timer]
OnBootSec=5min
OnCalendar=weekly
Persistent=true

[Install]
WantedBy=timers.target
```

Enable and start:
```bash
systemctl --user daemon-reload
systemctl --user enable --now aur-malware-check.timer
```

## Checking results

```bash
# See last run output
journalctl --user -u aur-malware-check

# Follow live output
journalctl --user -fu aur-malware-check

# Check timer status
systemctl --user status aur-malware-check.timer
```

## Desktop notifications

A critical notification fires when exit code 2 is returned (malicious package detected). This works automatically when:

- A notification daemon is running (e.g. `dunst`, `mako`, GNOME, KDE)
- The service runs as your user (not root)

No configuration needed. Pass `--no-notify` to suppress it.

### Two backends — `notify-send.sh` vs `notify-send`

These are **different tools**, and which one you have installed changes the behavior:

| Backend | Package | Behavior |
|---------|---------|----------|
| **`notify-send.sh`** | [`notify-send.sh`](https://aur.archlinux.org/packages/notify-send.sh) (AUR) | Notification gains a **Show Menu** button that opens the interactive menu |
| `notify-send` | `libnotify` (official repos) | Plain notification, no button — fallback |

The script prefers `notify-send.sh` if present and silently falls back to `notify-send`. `notify-send.sh` is a separate drop-in replacement that supports action buttons (`--action`); plain `notify-send` cannot run them.

### Interactive menu

When the **Show Menu** button is clicked, a terminal opens running `aur_malware_menu.sh` — an fzf menu to view the last log or re-run individual checks (systemd, eBPF, bpftool, npm/bun cache, PKGBUILD, ld.so.preload, XDG autostart, kernel modules).

Requirements for the button + menu:

- `notify-send.sh` (AUR) — the only backend that renders the button
- `fzf` — the menu picker
- A terminal: `$TERMINAL`, `terminator`, `kitty`, `xterm`, `gnome-terminal`, `xfce4-terminal`, or `mate-terminal`

Place `aur_malware_menu.sh` next to the main script (e.g. `~/.local/bin/`).

## Refreshing the package list

`--refresh` is included in the service above. It fetches the latest compromised package list from the Arch Linux HedgeDoc and writes it to `~/.config/aur-malware-check/package_list.txt` before each scan.

## Scan after every pacman transaction (optional)

The weekly timer catches things eventually; a `.path` unit watches `/var/log/pacman.log` and runs a scan **right after any install/upgrade/removal** — so a freshly installed compromised package is caught immediately.

This uses a **dedicated lightweight service** that runs **without `--refresh`** (uses the cached list the weekly timer keeps fresh) so each transaction triggers an instant, offline scan instead of a network round-trip.

**`~/.config/systemd/user/aur-malware-check-onchange.service`**
```ini
[Unit]
Description=AUR malware check (triggered after pacman transactions)

[Service]
Type=oneshot
ExecStart=%h/.local/bin/aur-malware-check.sh --full --all-time --log-file=%h/.config/aur-malware-check/last-scan.log
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aur-malware-check
```

**`~/.config/systemd/user/aur-malware-check.path`**
```ini
[Unit]
Description=Trigger AUR malware check after pacman transactions

[Path]
PathChanged=/var/log/pacman.log
Unit=aur-malware-check-onchange.service

[Install]
WantedBy=default.target
```

Enable and start:
```bash
systemctl --user daemon-reload
systemctl --user enable --now aur-malware-check.path
```

> The path unit only triggers when `/var/log/pacman.log` changes; systemd coalesces rapid writes (e.g. a big `-Syu`) so the scan runs once after the transaction settles. Use `--full` (cached list) here rather than `--refresh` to keep it fast and offline; freshness comes from the weekly timer.
