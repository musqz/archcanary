# Running archcanary via systemd

Run the scanner automatically with full coverage and a desktop notification if anything is found.

## Model

`--full` mixes two kinds of check: **system-level** ones that need root and are
machine-wide (kmod, eBPF, bpftool, ld.so.preload, systemd persistence, package
match) and **user-level** ones that live in a user's home (npm/bun/pkgbuild
caches, autostart, shell RCs). Running everything as root scans `/root` for the
user-level checks — wrong home, false positives. So the two are split:

```
system (root) — system-level checks:
  archcanary.service  --check-systemd --check-ebpf --check-bpftool
                             --check-ldso --check-kmod  (+ package/log checks)
     └─ writes /var/lib/archcanary/last-scan.log   (--no-notify)
  archcanary.timer    weekly + on boot
  archcanary.path     + -onchange.service  (after each pacman transaction)

  archcanary-notify.path (user) watches last-scan.log
     └─ notify.service: grep INFECTED → notify-send

user (you) — user-level checks:
  archcanary-user.service  --check-npm-cache --check-bun-cache
                                  --check-{yarn,pnpm}-cache --check-pkgbuild
                                  --check-autostart   (scans your real ~)
     └─ notifies itself on a detection (runs in your session)
  archcanary-user.timer    weekly + on boot
```

The root scan can't notify (no desktop session), so a user `.path` unit watches its result file and raises the alert. The user scan runs in your session, so it just calls `notify-send` itself.

## Quick setup (recommended)

`./install.sh --system` does all of this for you — it installs the system scan units, the user-level scan, and the notifier; creates `/var/lib/archcanary/`; seeds the package lists and the system-wide DKMS, systemd, and bpftool allowlists; enables the system timer + pacman-trigger, the user timer, and the notifier; and migrates away any old user-scope scan units:

```bash
./install.sh --system
```

The rest of this document describes the units it installs, for reference or manual setup.

> The system components are required — `install.sh --system` installs the root-accessible script, the root helper, the polkit policy, **and** the bundled package lists under `/usr/lib/archcanary/` so the root scan can find them (root's `$HOME` is `/root`, which is not seeded).

## 1. System scan (root)

**`/etc/systemd/system/archcanary.service`**
```ini
[Unit]
Description=archcanary system scan (root)
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
StateDirectory=archcanary
ExecStart=/usr/lib/archcanary/archcanary.sh --refresh --check-systemd --check-ebpf --check-bpftool --check-ldso --check-kmod --no-notify --log-file=/var/lib/archcanary/last-scan.log
```

> `StateDirectory=archcanary` makes systemd create `/var/lib/archcanary` (mode 0755, root) automatically. This runs only the **system-level** checks (plus the always-on package/log checks) — the ones that need root and are machine-wide. The user-level checks run in section 3 as your user. `--no-notify` because root has no desktop session — section 2 handles alerts.

**`/etc/systemd/system/archcanary.timer`**
```ini
[Unit]
Description=Run archcanary system scan weekly and on boot

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
sudo systemctl enable --now archcanary.timer
```

## 2. Desktop notification (user)

**`~/.config/systemd/user/archcanary-notify.path`**
```ini
[Unit]
Description=Watch for archcanary scan results
# A transient trigger burst must never wedge the watcher into a permanent
# 'failed' (start-limit-hit) state and silence detections.
StartLimitIntervalSec=0

[Path]
# PathChanged (IN_CLOSE_WRITE) fires once when the writer closes the file, not
# on every write. The scan streams last-scan.log line-by-line via tee, so
# PathModified would fire dozens of times per scan and trip the start limit.
PathChanged=/var/lib/archcanary/last-scan.log
Unit=archcanary-notify.service

[Install]
WantedBy=default.target
```

**`~/.config/systemd/user/archcanary-notify.service`**
```ini
[Unit]
Description=Notify on archcanary malware detection
# Don't rate-limit: the path unit may trigger this oneshot a few times around a
# scan; a burst must not leave it stuck 'failed' (start-limit-hit).
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'grep -q "RESULT: INFECTED" /var/lib/archcanary/last-scan.log && notify-send -u critical -i dialog-warning "archcanary: malicious package detected" "Open Archcanary to review." || true'
```

Enable and start:
```bash
systemctl --user daemon-reload
systemctl --user enable --now archcanary-notify.path
```

> The path unit fires once when the root scan finishes writing the result file (it watches for file close, not every write); the service notifies only when a detection is present. Needs a notification daemon (`dunst`, `mako`, GNOME, KDE) and `libnotify`. To review/remediate, open **Archcanary** from your app launcher.

## 3. User-level scan (your session)

Runs the user-level checks **as you**, so they scan your real `~/.cache` and `~/.config` (not root's) and resolve autostart `Exec=` names against your PATH. Running in your session, it raises its own notification on a detection — no `--no-notify`, no separate notifier needed.

**`~/.config/systemd/user/archcanary-user.service`**
```ini
[Unit]
Description=archcanary user-level scan

[Service]
Type=oneshot
ExecStart=%h/.local/bin/archcanary --check-npm-cache --check-bun-cache --check-yarn-cache --check-pnpm-cache --check-pkgbuild --check-autostart --log-file=%h/.cache/archcanary/last-user-scan.log
```

**`~/.config/systemd/user/archcanary-user.timer`**
```ini
[Unit]
Description=Run archcanary user-level scan weekly and on boot

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
systemctl --user enable --now archcanary-user.timer
```

## 4. Scan after every pacman transaction (optional)

A **system** path unit watches `/var/log/pacman.log` and runs an offline (no `--refresh`) system-level scan right after any install/upgrade/removal, so a freshly installed compromised package is caught immediately. The section-2 user notifier covers these runs too (same result file).

**`/etc/systemd/system/archcanary-onchange.service`**
```ini
[Unit]
Description=archcanary system scan (after pacman transaction)

[Service]
Type=oneshot
StateDirectory=archcanary
ExecStart=/usr/lib/archcanary/archcanary.sh --check-systemd --check-ebpf --check-bpftool --check-ldso --check-kmod --no-notify --log-file=/var/lib/archcanary/last-scan.log
```

**`/etc/systemd/system/archcanary.path`**
```ini
[Unit]
Description=Trigger archcanary scan after pacman transactions

[Path]
PathChanged=/var/log/pacman.log
Unit=archcanary-onchange.service

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now archcanary.path
```

> The path unit only triggers when `/var/log/pacman.log` changes; systemd coalesces rapid writes (e.g. a big `-Syu`) so the scan runs once after the transaction settles. Runs offline against the cached list; freshness comes from the weekly timer's `--refresh`.

## Checking results

```bash
# Last system-scan output (root-owned)
sudo cat /var/lib/archcanary/last-scan.log
# Last user-scan output
cat ~/.cache/archcanary/last-user-scan.log

# Or via the journal
journalctl -u archcanary            # system scan
journalctl --user -u archcanary-user   # user scan

# Timer / unit status
systemctl status archcanary.timer
systemctl --user status archcanary-user.timer archcanary-notify.path
```

## Why the split?

The system scan runs `--check-kmod`, `--check-ebpf`, and `--check-bpftool`, which need root to read kernel-module attribution and enumerate loaded eBPF programs — run without root they're skipped and the scan reports `INCOMPLETE` (exit 1). The user-level checks (npm/bun/pkgbuild caches, autostart, shell RCs) are the opposite: they must run **as you** so they see your real `~/.cache`/`~/.config` and resolve `Exec=` names against your PATH. Run as root they'd scan `/root` — missing your data and false-flagging root's own session relics. Hence two scans, each in the right context.
