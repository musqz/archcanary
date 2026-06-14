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
ExecStart=%h/.local/bin/aur-malware-check.sh --refresh --full --all-time
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aur-malware-check
```

**`~/.config/systemd/user/aur-malware-check.timer`**
```ini
[Unit]
Description=Run AUR malware check weekly and on boot

[Timer]
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

The script calls `notify-send` with urgency `critical` when exit code 2 is returned (malicious package detected). This works automatically when:

- `libnotify` is installed (`pacman -S libnotify`)
- A notification daemon is running (e.g. `dunst`, `mako`, GNOME, KDE)
- The service runs as your user (not root)

No configuration needed — the notification fires automatically on a positive result.

## Refreshing the package list

`--refresh` is included in the service above. It fetches the latest compromised package list from the Arch Linux HedgeDoc and writes it to `~/.config/aur-malware-check/package_list.txt` before each scan.
