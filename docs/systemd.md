# Running aur-malware-check via systemd

Run the scanner automatically with full coverage and a desktop notification if anything is found.

## Model

`--full` mixes two kinds of check: **system-level** ones that need root and are
machine-wide (kmod, eBPF, bpftool, ld.so.preload, systemd persistence, package
match) and **user-level** ones that live in a user's home (npm/bun/pkgbuild
caches, autostart, shell RCs). Running everything as root scans `/root` for the
user-level checks — wrong home, false positives. So the two are split:

```
system (root) — system-level checks:
  aur-malware-check.service  --check-systemd --check-ebpf --check-bpftool
                             --check-ldso --check-kmod  (+ package/log checks)
     └─ writes /var/lib/aur-malware-check/last-scan.log   (--no-notify)
  aur-malware-check.timer    weekly + on boot
  aur-malware-check.path     + -onchange.service  (after each pacman transaction)

  aur-malware-check-notify.path (user) watches last-scan.log
     └─ notify.service: grep INFECTED → notify-send

user (you) — user-level checks:
  aur-malware-check-user.service  --check-npm-cache --check-bun-cache
                                  --check-{yarn,pnpm}-cache --check-pkgbuild
                                  --check-autostart   (scans your real ~)
     └─ notifies itself on a detection (runs in your session)
  aur-malware-check-user.timer    weekly + on boot
```

The root scan can't notify (no desktop session), so a user `.path` unit watches its result file and raises the alert. The user scan runs in your session, so it just calls `notify-send` itself.

## Quick setup (recommended)

`./install.sh --system` does all of this for you — it installs the system scan units, the user-level scan, and the notifier; creates `/var/lib/aur-malware-check/`; seeds the package lists and the system-wide DKMS allowlist; enables the system timer + pacman-trigger, the user timer, and the notifier; and migrates away any old user-scope scan units:

```bash
./install.sh --system
```

The rest of this document describes the units it installs, for reference or manual setup.

> The system components are required — `install.sh --system` installs the root-accessible script, the root helper, the polkit policy, **and** the bundled package lists under `/usr/lib/aur-malware-check/` so the root scan can find them (root's `$HOME` is `/root`, which is not seeded).

## 1. System scan (root)

**`/etc/systemd/system/aur-malware-check.service`**
```ini
[Unit]
Description=AUR malware check (system-level scan, root)
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
StateDirectory=aur-malware-check
ExecStart=/usr/lib/aur-malware-check/aur-malware-check.sh --refresh --all-time --check-systemd --check-ebpf --check-bpftool --check-ldso --check-kmod --no-notify --log-file=/var/lib/aur-malware-check/last-scan.log
```

> `StateDirectory=aur-malware-check` makes systemd create `/var/lib/aur-malware-check` (mode 0755, root) automatically. This runs only the **system-level** checks (plus the always-on package/log checks) — the ones that need root and are machine-wide. The user-level checks run in section 3 as your user. `--no-notify` because root has no desktop session — section 2 handles alerts.

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

## 3. User-level scan (your session)

Runs the user-level checks **as you**, so they scan your real `~/.cache` and `~/.config` (not root's) and resolve autostart `Exec=` names against your PATH. Running in your session, it raises its own notification on a detection — no `--no-notify`, no separate notifier needed.

**`~/.config/systemd/user/aur-malware-check-user.service`**
```ini
[Unit]
Description=AUR malware check (user-level scan)

[Service]
Type=oneshot
ExecStart=%h/.local/bin/aur-malware-check.sh --all-time --check-npm-cache --check-bun-cache --check-yarn-cache --check-pnpm-cache --check-pkgbuild --check-autostart --log-file=%h/.cache/aur-malware-check/last-user-scan.log
```

**`~/.config/systemd/user/aur-malware-check-user.timer`**
```ini
[Unit]
Description=Run AUR malware user-level check weekly and on boot

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
systemctl --user enable --now aur-malware-check-user.timer
```

## 4. Scan after every pacman transaction (optional)

A **system** path unit watches `/var/log/pacman.log` and runs an offline (no `--refresh`) system-level scan right after any install/upgrade/removal, so a freshly installed compromised package is caught immediately. The section-2 user notifier covers these runs too (same result file).

**`/etc/systemd/system/aur-malware-check-onchange.service`**
```ini
[Unit]
Description=AUR malware check (system-level scan, after pacman transaction)

[Service]
Type=oneshot
StateDirectory=aur-malware-check
ExecStart=/usr/lib/aur-malware-check/aur-malware-check.sh --all-time --check-systemd --check-ebpf --check-bpftool --check-ldso --check-kmod --no-notify --log-file=/var/lib/aur-malware-check/last-scan.log
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

> The path unit only triggers when `/var/log/pacman.log` changes; systemd coalesces rapid writes (e.g. a big `-Syu`) so the scan runs once after the transaction settles. Runs offline against the cached list; freshness comes from the weekly timer's `--refresh`.

## Checking results

```bash
# Last system-scan output (root-owned)
sudo cat /var/lib/aur-malware-check/last-scan.log
# Last user-scan output
cat ~/.cache/aur-malware-check/last-user-scan.log

# Or via the journal
journalctl -u aur-malware-check            # system scan
journalctl --user -u aur-malware-check-user   # user scan

# Timer / unit status
systemctl status aur-malware-check.timer
systemctl --user status aur-malware-check-user.timer aur-malware-check-notify.path
```

## Migrating from the old user service

Earlier versions ran the scan as a **user** service (`~/.config/systemd/user/aur-malware-check.{service,timer}`). Because that runs without root, the kmod/eBPF/bpftool checks are skipped and the scan now reports `INCOMPLETE` (exit 1). Disable the old user units and use the system scan above instead:

```bash
systemctl --user disable --now aur-malware-check.timer
rm -f ~/.config/systemd/user/aur-malware-check.service \
      ~/.config/systemd/user/aur-malware-check.timer
```

## Why the split?

The system scan runs `--check-kmod`, `--check-ebpf`, and `--check-bpftool`, which need root to read kernel-module attribution and enumerate loaded eBPF programs — run without root they're skipped and the scan reports `INCOMPLETE` (exit 1). The user-level checks (npm/bun/pkgbuild caches, autostart, shell RCs) are the opposite: they must run **as you** so they see your real `~/.cache`/`~/.config` and resolve `Exec=` names against your PATH. Run as root they'd scan `/root` — missing your data and false-flagging root's own session relics. Hence two scans, each in the right context.
