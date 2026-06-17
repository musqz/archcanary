# Running aur-malware-check via systemd

Run the scanner automatically with the **full** picture — including the root-only checks (kmod, eBPF, bpftool) — and a desktop notification if anything is found.

## Model

A complete scan needs root, but desktop notifications need your user session. So it is split in two:

```
system (root):
  aur-malware-check.service   --refresh --full --all-time --no-notify
     └─ writes /var/lib/aur-malware-check/last-scan.log   (complete, no INCOMPLETE warning)
  aur-malware-check.timer     weekly + on boot

user:
  aur-malware-check-notify.path      watches last-scan.log
     └─ aur-malware-check-notify.service:  grep INFECTED → notify-send
```

The root scan runs all checks (so the result is trustworthy, not `INCOMPLETE`) but does **not** notify; the user notifier reads the shared result file and raises the desktop alert.

> Requires the system components — run `sudo ./install.sh --system` first. That installs the root-accessible script, the root helper, the polkit policy, **and** the bundled package lists under `/usr/lib/aur-malware-check/` so the root scan can find them (root's `$HOME` is `/root`, which is not seeded).

## 1. System scan (root)

**`/etc/systemd/system/aur-malware-check.service`**
```ini
[Unit]
Description=AUR malware check (full scan, root)
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
StateDirectory=aur-malware-check
ExecStart=/usr/lib/aur-malware-check/aur-malware-check.sh --refresh --full --all-time --no-notify --log-file=/var/lib/aur-malware-check/last-scan.log
```

> `StateDirectory=aur-malware-check` makes systemd create `/var/lib/aur-malware-check` (mode 0755, root) automatically. Running as root, `--full` performs the kmod/eBPF/bpftool checks, so the scan is complete. `--no-notify` because root has no desktop session — step 2 handles alerts.

**`/etc/systemd/system/aur-malware-check.timer`**
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
sudo systemctl daemon-reload
sudo systemctl enable --now aur-malware-check.timer
```

## 2. Desktop notification (user)

**`~/.config/systemd/user/aur-malware-check-notify.path`**
```ini
[Unit]
Description=Watch for AUR malware scan results

[Path]
PathModified=/var/lib/aur-malware-check/last-scan.log
Unit=aur-malware-check-notify.service

[Install]
WantedBy=default.target
```

**`~/.config/systemd/user/aur-malware-check-notify.service`**
```ini
[Unit]
Description=Notify on AUR malware detection

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'grep -q "RESULT: INFECTED" /var/lib/aur-malware-check/last-scan.log && notify-send -u critical -i dialog-warning "AUR: malicious package detected" "Open AUR Malware Check to review." || true'
```

Enable and start:
```bash
systemctl --user daemon-reload
systemctl --user enable --now aur-malware-check-notify.path
```

> The path unit fires whenever the root scan rewrites the result file; the service notifies only when a detection is present. Needs a notification daemon (`dunst`, `mako`, GNOME, KDE) and `libnotify`. To review/remediate, open **AUR Malware Check** from your app launcher.

## 3. Scan after every pacman transaction (optional)

Same split — a **system** path unit watches `/var/log/pacman.log` and runs an offline (no `--refresh`) full scan right after any install/upgrade/removal, so a freshly installed compromised package is caught immediately. The step-2 user notifier covers these runs too (same result file).

**`/etc/systemd/system/aur-malware-check-onchange.service`**
```ini
[Unit]
Description=AUR malware check (after pacman transaction)

[Service]
Type=oneshot
StateDirectory=aur-malware-check
ExecStart=/usr/lib/aur-malware-check/aur-malware-check.sh --full --all-time --no-notify --log-file=/var/lib/aur-malware-check/last-scan.log
```

**`/etc/systemd/system/aur-malware-check.path`**
```ini
[Unit]
Description=Trigger AUR malware check after pacman transactions

[Path]
PathChanged=/var/log/pacman.log
Unit=aur-malware-check-onchange.service

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now aur-malware-check.path
```

> The path unit only triggers when `/var/log/pacman.log` changes; systemd coalesces rapid writes (e.g. a big `-Syu`) so the scan runs once after the transaction settles. Uses `--full` against the cached list (offline); freshness comes from the weekly timer's `--refresh`.

## Checking results

```bash
# Last scan output (root-owned)
sudo cat /var/lib/aur-malware-check/last-scan.log

# Or via the journal
journalctl -u aur-malware-check
journalctl -u aur-malware-check-onchange

# Timer / unit status
systemctl status aur-malware-check.timer
systemctl --user status aur-malware-check-notify.path
```

## Migrating from the old user service

Earlier versions ran the scan as a **user** service (`~/.config/systemd/user/aur-malware-check.{service,timer}`). Because that runs without root, the kmod/eBPF/bpftool checks are skipped and the scan now reports `INCOMPLETE` (exit 1). Disable the old user units and use the system scan above instead:

```bash
systemctl --user disable --now aur-malware-check.timer
rm -f ~/.config/systemd/user/aur-malware-check.service \
      ~/.config/systemd/user/aur-malware-check.timer
```

## Why root?

`--full` includes `--check-kmod`, `--check-ebpf`, and `--check-bpftool`, which need root to read kernel-module attribution and enumerate loaded eBPF programs. Run without root, those three are skipped and the scan reports `INCOMPLETE` (exit 1) rather than a misleading `CLEAN`. Running the scan as root (the system service) is what makes the automated result complete and trustworthy.
