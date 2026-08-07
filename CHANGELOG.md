# Changelog

## v0.1.28 (unreleased)

- Fix: `--scan-all-homes` forwarded the invoking (sudo) user's own list-path flags (`--malicious-npm-list=`, `--package-list=`, etc.) into every other local user's per-user child scan. Those resolve into the invoking user's own home, which a second real account has no read access into — the list looked missing, the self-heal bundled-default copy then also failed writing into someone else's home, and the whole per-user scan came back an unparseable WARNING. Each child now resolves its own list paths from its own `$HOME`, matching `archcanary-user.service`'s existing behavior. Reported live against a freshly created second local account.
- Fix: `install.sh --system` seeded `/usr/lib/archcanary/*.txt` (the bundled-default threat lists every non-root user's first run falls back to) with a plain `cp` and no explicit mode, so the result inherited root's umask at install time — on a restrictive umask this left the files unreadable by anyone but root, breaking that same fallback for every user but root. Now `chmod 644`'d explicitly after the copy.
- Added: `--scan-user=NAME` — runs `--scan-all-homes`'s same npm/bun/yarn/pnpm/pkgbuild/autostart checks against one specific user's home instead of enumerating everyone. Repeatable (`--scan-user=alice --scan-user=bob`), de-duped, needs root, mutually exclusive with `--scan-all-homes`. For checking a single newly-created or flagged account without sweeping every local user.

## v0.1.27 (2026-08-06)

- Fix: `configs/yay-init.lua`'s aur-audit RED warning matched by package name only, so a once-flagged package kept warning on every future install even after a newer version was rescanned clean — reported live on `firefox-pure`. `--refresh` now also captures the flagged version into `aur_audit_red_versions.txt` (RED only; BLACK's block stays unconditional); the hook compares it against the installing PKGBUILD's own `pkgver`/`pkgrel` and only keeps full severity on an exact match. Marker bumped to `(v6)`.
- Fix: `archcanary-gui`'s yad dialogs jumped every time you resized one, since `--center` maps to GTK's `GTK_WIN_POS_CENTER_ALWAYS`, which GTK re-applies on every resize instead of just once at open. Replaced with a one-time computed `--posx`/`--posy` (via `xdotool`, falling back to `--center` if it's not installed) across every sizable dialog in `archcanary-gui.sh`.
- Added: a `LOG_HIST` match (historical — package no longer installed) now only counts as a WARNING the first time. A repeat scan of the exact same install event prints `LOG_HIST_SEEN` instead — informational only, like `LOG_OLD` — so a name you've already reviewed doesn't keep raising the exit code on every future scan. A genuinely new install of the same package name is still flagged fresh. State tracked in `~/.cache/archcanary/log_hist_seen.txt`. Prompted by a live report where a since-removed `discord-qt` install kept re-triggering a WARNING on every scan.
- Changed: `configs/yay-init.lua`'s pattern-block/aur-audit hook messages (block, warn, and the "clean" confirmation) are now a dash-padded `ARCHCANARY:` banner with the verdict in caps — e.g. `ARCHCANARY: pkg # ---------- PKGBUILD CHECKS CLEAN ---------- #`. The old plain `archcanary: pkg PKGBUILD checks clean` line looked identical to the dozens of generic `==>` status lines makepkg/yay print around it, making it easy to miss in a real build's output. Marker bumped to `(v8)` (an intermediate wording pass had already used up `(v7)` without landing in a release, so the two never diverged under the same marker in anything actually shipped).

## v0.1.26 (2026-08-05)

- Added: `--scan-all-homes` — enumerates real local users and runs the npm/bun/yarn/pnpm/pkgbuild/autostart checks against each of their homes, not just yours (privilege-dropped per user via `sudo -u`). Closes the gap where `archcanary-user.timer` only covers whoever enables it themselves. New `archcanary-scan-all-homes.service`/`.timer`, opt-in and off by default.
- Added: `--help`/`-h` for `install.sh` (usage, uninstall, what `--system` sets up).
- Added: check-summary rows are now numbered to match their detail section.
- Fix: `install.sh --system` called `sudo` per-command (~20+ invocations) — now funnels every root step through one script (`lib/archcanary-root-install.sh`), so a restricted sudoers config only needs to allowlist one command. Reported on the Arch Linux forum.
- Fix: unrecognized CLI flags were silently ignored — or, in `install.sh`, misread as a bin-dir path — instead of erroring; both now reject with a clear message.
- Fix: the "Infected" GUI dialog could render wildly oversized and unresizable on some GTK/theme setups. Switched from a plain `--text=` label to `--text-info`, which actually respects `--height`. Reported on the Arch Linux forum.
- Fix: `configs/yay-init.lua`'s PKGBUILD-scan hook ran on `AURPreInstall`, before yay's own diff/edit review menus. Moved to `AURPostDownload` so the scan runs after human review, not before it.
- Fix: yay's Lua hook was seeded even when yay wasn't installed; now gated on `command -v yay`, matching the existing paru check.
- Fix: a scan without `--check-lynis`/`--run-lynis` was marked `INCOMPLETE` for missing Lynis data it never asked for.
- Docs: noted paru's `PreBuildCommand` hook has the same before-review timing as yay's old hook, with no equivalent fix available — paru exposes no post-review hook (confirmed in paru's own source). Sudoers example scoped to the local hostname instead of `ALL`.
- Docs: added a PKGBUILD-reading guide, later rewritten as a practical reference; fixed a false timeline implication in the Chrome RAT writeup.
- Chore: dropped stale `python-isounidecode` from the package list.

## v0.1.25 (2026-08-04)

- Docs: added two AUR incidents to `SOURCES.md` that surfaced while comparing traur's old pattern database against archcanary's own incident record — Acroread (2018, orphan-package-takeover, curl download-and-persist, systemd persistence; narrative-only, since `acroread` is a legitimate package today and archcanary's cutoff mechanism can't express a bounded compromise window) and the `google-chrome-stable` RAT (2025, a brand-new account's `.install` scriptlet running Python download-and-execute on every Chrome launch; confirmed as a separate incident from the already-tracked CHAOS RAT wave). Added `google-chrome-stable`/`chrome`/`google-chrome-bin`/`ttf-mac-fonts-all` to `community_reports.txt` — verified none currently exist as real AUR packages, so zero collision risk.
- Removed: traur integration (the optional AUR trust-scoring pacman hook, `Sohimaster/traur`) has been dropped entirely — the `--doctor` dependency/pacman-hook check, the GUI's "Trust scan (traur)" menu item and its click handler, the README/SOURCES/my-setup/overview/man-page mentions, the `docs/false-positives.md` register (entirely about a traur-specific signal, with nothing left to document once traur is gone), and the `packaging/archcanary.install` hints. Prompted by checking on a report that the upstream repo "hasn't been touched in 6 months": confirmed via AUR's RPC data and GitHub — last commit 2026-02-25 (~5.3 months), last *merged* PR was the project's very first one (2026-02-07, nothing merged since despite 4 substantive community PRs open since mid-June), flagged out-of-date on AUR days before this check, and an "Is TRAUR Abandoned?" issue opened the same day. Community discussion (upstream issue #19) also surfaced an architectural gap worth noting: traur's hook is a pacman `PreTransaction` hook, which fires *after* `makepkg` has already run `build()` — for the actual AUR malware vector (a payload inside `build()`), the malicious code has already executed as the user by the time traur scans anything; it can only block installation, not the execution that already happened. Chose removal over forking-and-maintaining it ourselves — a 279-signal Rust codebase is a different scale/stack commitment than archcanary's own bash-only checks, and the project already has precedent for this call (aurscan was dropped the same way, not adopted, when it stopped being worth the integration burden). archcanary's own checks and the yay/paru pre-build hooks are entirely unaffected — none of them ever depended on traur. `archcanary-gui.sh`'s positional menu arrays (`LABELS`/`FLAGS`/`NEEDS_ROOT`/`STATUS`) were reindexed since traur's row sat in the middle (old index 13); verified the resulting arrays and menu output directly rather than trusting the edit by eye.
- Fix: `check_logs`' aur-audit black/red matches ignored how old the pacman.log entry was relative to when the flag was actually assigned — reported live: a user's `linux-lqx` (Liquorix kernel) install/upgrade entries from 2021 were flagged `LOG_HIT`/INFECTED because the package is *currently* red-flagged, with no indication those 2021 entries had anything to do with whatever's flagged today. Root cause: `--refresh` only ever stored the package *name* from the aur-audit API, discarding the `pubDateTs` field (the flagged version's own AUR publish date) it already provides — `check_logs` had no date to correlate against, so it deliberately never downgraded this source at all (see the entry below on the base-list/CHAOS-RAT fix, which explicitly excluded aur-audit for exactly this reason). `--refresh` now also captures `pubDateTs` into new `aur_audit_{black,red}_dates.txt` companion files (the plain-name `aur_audit_{black,red}.txt` files are untouched — `configs/yay-init.lua`'s Lua hook reads those directly and needs them to stay one name per line); `check_logs` uses the per-package date the same way it already used the base list's/CHAOS RAT's fixed campaign-start dates, downgrading a log entry that predates the flagged version to `LOG_OLD`. Falls back to the old never-downgrade behavior for any package with no date on file yet (not re-refreshed since this shipped). Verified end-to-end against the real live feed and the reporter's exact log entries — all 5 now correctly show `LOG_OLD` instead of `LOG_HIT`.
- Fix: `--color` silently accepted any value instead of validating it — reported live: `--color=#CAD451` (a hex code, not one of the three supported values) produced no error, just silently fell through to colorless output with no indication anything was wrong. `--format` already validates and errors on garbage (`--format=xml` → "Error: --format must be 'text' or 'json'"); `--color`'s case statement had no equivalent fallback branch. Now errors the same way: "Error: --color must be 'auto', 'always', or 'never' (got '...')", exit 1.
- Added: `configs/yay-init.lua`'s two `AURPreInstall` hooks (pattern block, aur-audit black/red check) now print `archcanary: <pkg> PKGBUILD checks clean` when neither finds anything, matching `traur`'s own "All packages look clean" line. Found live while verifying the newly-ported patterns below actually fire in a real `yay` build: on a clean PKGBUILD the hooks correctly ran and found nothing, but stayed completely silent — indistinguishable from the hooks never having been wired up at all, which is exactly what it looked like at first. Merged the two separate `AURPreInstall` registrations into one (header marker bumped to `(v4)`; `--doctor` updated to match) so there's a single combined confirmation line per package instead of a potential two; the aur-audit "red" (warn, not abort) case also suppresses the clean line, since printing "clean" right next to a review-this warning would be self-contradictory.
- Added: `check_pkgbuild_caches`' obfuscation detections now also run *before* a build, not just against whatever's already sitting in an AUR helper's cache. `configs/yay-init.lua`'s `AURPreInstall` pattern block only ever covered 2 hardcoded incident strings plus a curl/wget-pipe check — missing 6 of the bash check's 8 patterns entirely (base64-decode-to-shell, eval+subshell, printf hex/octal, variable-split command reassembly, chained ANSI-C hex/octal escapes, rev/tr-to-shell). Ported all 6 into Lua (header marker bumped to `(v3)`; `--doctor` updated to match) — Lua patterns have no counted-repetition syntax, so the chained-hex-escape check (which specifically requires 3+ consecutive escapes, to avoid the exact false positive on `read -d $'\0'` this same check already had to fix once in bash — see the `(v)0.1.23` entry below) is a small hand-written counting function instead of a table pattern, verified against both the required-match and required-no-match cases by hand-tracing. paru gets the same coverage for the first time via its own native `PreBuildCommand` hook (`~/.config/paru/paru.conf`, `[bin]` section) — new `configs/paru-hook.conf`, seeded by `install.sh` only when paru is installed and only if no `PreBuildCommand` is already configured (never overwrites an existing one, same rule as yay's `init.lua`), removed cleanly on uninstall. Confirmed against paru's own source that a nonzero `PreBuildCommand` exit genuinely aborts that package's build, not just a warning; the seeded command runs `archcanary --check-pkgbuild` scoped to just that package's own build directory (`PKGBUILD_CACHE_DIRS=.`) and fails open if archcanary isn't on `$PATH`. Along the way, gave real behavior to `--doctor=paru`, which has been a dead alias (routing to the `external` section but checking nothing paru-specific) since the unrelated `aurscan` tool that originally wired it up was removed.
- Fix: `check_pkgbuild_caches`' undocumented-ELF-binary detection (added in v0.1.24) false-positived on legitimate `-bin` packages — reported live on `pistol-bin` and `coolercontrol-bin`, both long-standing, multi-contributor packages. Root cause: a `-bin` package's `source_$CARCH=()` often points straight at a raw binary URL, and `makepkg` downloads it into the *top level* of the build dir (the same place `PKGBUILD` lives) as a normal part of building — `src/` only gets a symlink back to it. That's indistinguishable by plain file presence from something an attacker committed directly to the AUR git tree, which is what the check actually meant to catch. Reproduced end-to-end against the real `pistol-bin` AUR repo (`git clone` + `makepkg -o`): the downloaded binary shows up as `??` (untracked) in `git status`. The check now only flags an ELF binary that's actually tracked in the package's own git repo (`git ls-files --error-unmatch`) — a real commit, not a local build artifact. No git repo at all (non-`git`-based cache layout) is treated the same as untracked, erring toward not flagging rather than a guaranteed false positive on every raw-binary `-bin` package.
- Fix: the same report also flagged that the remediation text told the user to "remove the flagged cache dir(s)... then re-fetch... and diff it against what's flagged above" — backwards, since you need the flagged copy *to* diff against; deleting it first defeats the point. Reworded to diff against a fresh clone first (without deleting the local cache), then act on the result: still present upstream → don't build, report it; already fixed upstream → the local cache was just stale, safe to delete and re-fetch.
- Fix: `check_logs` (Check 2, "Historical pacman logs") matched a pacman.log entry's package *name* against the loaded lists with no awareness of *when* that entry happened relative to when the name actually became compromised — reported live: `python-future` and `clang15` were flagged with install/upgrade dates in 2023 and early-to-mid 2024, years before the malicious-AUR campaign that put those names on `package_list.txt` even started (the earliest documented malicious commit is 2026-06-09, per `SOURCES.md`). A 2023 install of a name that only turned malicious in 2026 was flagged identically to a genuinely recent one. Each match now compares its own log date against a per-source cutoff (base list: 2026-06-09; CHAOS RAT: 2025-07-22, its own documented discovery date; Community Reports and the aur-audit black/red feed get no cutoff at all, since neither has a fixed campaign date to anchor one) — a match predating its source's cutoff now prints as a new `LOG_OLD` tier instead of `LOG_HIT`/`LOG_HIST`, staying fully visible (never hidden, matching this project's read-only/detect-and-report philosophy) but exit-code-neutral, since it almost certainly predates any real compromise. Takes priority over the currently-installed/historical split: a still-installed package whose only logged actions predate the cutoff couldn't have pulled a compromised build either, since a rebuild always produces a new log line. Added the check's first-ever regression tests, which needed a small testability fix alongside it — the caller's `[[ -f /var/log/pacman.log ]]` gate was a hardcoded literal path ignoring `$PACMAN_LOG_GLOB` entirely, so no fixture-based test could ever reach `check_logs` without a real system log at that exact path; the gate now expands the same glob the function already does internally.

## v0.1.24 (2026-08-03)

- Added: `archcanary-gui`'s scan-result window gets a Save button — previously results only ever wrote to `/tmp` and vanished when the window closed, with no way to keep a copy (the CLI already had `--log-file` for this). Opens a save-file picker defaulting to a remembered directory (falling back to the CLI's own `--log-file` default the first time), with the same auto-timestamped filename a CLI run would use; the chosen directory persists to `~/.config/archcanary/env`. Wired into both scan-display code paths — the plain non-root window and the separate pkexec-elevated one used by root-requiring checks (eBPF, bpftool, kmod, Lynis, pacman integrity, Full scan) — which had been missing the button entirely at first, since they're two independent code paths that don't share logic. A same-day follow-up fixed a `set -e` footgun (a bare `[[ cond ]] &&` at the top level killed the whole GUI silently on first launch with no `GUI_LOG_SAVE_DIR` set yet), and a `/code-review` pass caught the ~18-line save flow duplicated verbatim between the two code paths (factored into one `_save_scan_log()` helper) plus `--aur-audit-enable`/`-disable`'s own env-file writer clobbering the GUI's saved directory setting on its next toggle (now preserves it, matching the GUI's own write-back).
- Fix: `check_pkginteg` labeled every pacman file mismatch a WARNING (exit 2) even when none of the mismatches were actually binaries — i.e. even when nothing was actually wrong, just expected hook-driven drift (see below). Only ELF-classified mismatches now drive the WARNING label and exit code; non-binary mismatches stay visible but read as an informational note instead. Added fixture-based regression coverage (a `PACMAN_CMD` override, matching the existing `LSMOD_CMD`/`DKMS_CMD`/`BPFTOOL_CMD` pattern) — the classification logic had only been verified manually against live machine state until now.
- Fix: `check_pkginteg` suggested "Reinstall to restore the original files" for every mismatch, including non-binary ones caused by a pacman hook or the package's own tooling regenerating that exact file on every install/upgrade by design (e.g. `60-depmod.hook`, `update-vlc-plugin-cache.hook`, Firefox/NetworkManager branding hooks, GHC/pacman-mirrors caches) — reinstalling doesn't fix any of those, since the hook re-diverges the file immediately after. Reported live: none of a real machine's 17 mismatches were binaries, so the suggestion was wrong for the entire batch. The hint now only shows when at least one of a package's mismatches is a compiled binary (the same ELF magic-byte check `check_pkgbuild_caches` already relies on); non-binary-only packages get an explanation instead.
- Fix: `check_pkginteg` merged pacman's stdout and stderr into one capture (fixing the previous release's missed-warnings bug) but interleaved their writes unpredictably — stdout is block-buffered off a TTY, stderr isn't, so a stdout line's tail could end up glued mid-word onto a stderr line's head with no newline between them. Reported live (`"backup file: libvirtwarning: libvirt: ..."`, real text from two different lines fused together). stderr now captures to a temp file instead of sharing stdout's fd, so both streams stay clean before being concatenated as text.
- Added: `check_pkgbuild_caches` flags an ELF binary sitting directly next to a package's `PKGBUILD` in an AUR helper cache (rather than under `src/`/`pkg/`, which only exist as build output after `makepkg` runs) — a source-based PKGBUILD has no legitimate reason to ship a compiled binary in its own git tree, even `-bin` packages fetch theirs via `source=()` into `src/` at build time. Prompted by an Arch mailing-list critique that blocklist-only detection misses this exact attack shape; the check's existing obfuscation patterns only ever covered shell-level tricks (base64, eval, hex encoding), not embedded binaries. Follows symlinks before the file-type test so a symlink to an ELF binary can't evade the check the same way. Verified against a real yay cache (including `brave-bin`, `firedragon-bin`) with zero false positives.
- Fix: 21 of `check_*`'s 33 `WARNING` call sites gave no guidance on what to do about the finding, unlike `check_autostart`'s and `check_kmod`'s existing hints. Added hints to the 9 sites that didn't need new ecosystem-specific removal commands: `check_current` now suggests `sudo pacman -Rns`, `check_systemd`/`check_bpftool` mention the allowlist mechanism they already support but never surfaced, `check_ebpf` adds investigative context (no allowlist exists there by design), `check_autostart`'s shell-RC branch gets a "remove the line" hint, `check_pkgbuild_caches` gets one shared cleanup hint, and `check_pkginteg` gets a reinstall hint with resolved package names. Also fixed a real bug found while verifying the last one: `check_pkginteg` captured `pacman -Qkk` with stderr discarded (`2>/dev/null`) — exactly where pacman prints the checksum-mismatch "warning:" lines the check exists to catch, so it had likely never detected a real mismatch before this fix.
- Fix: `check_kmod`'s untracked-DKMS warning gave no remediation hint at all, unlike `check_autostart`'s (reported on the forum for `broadcom-wl`). Unlike autostart's single-cause case, "untracked" here has two opposite-action causes archcanary can't distinguish — a proprietary driver never meant to be pacman-tracked (allowlist it) versus a stale DKMS registration left behind after its owning package was removed (clean it up) — so the hint shows both paths and lets the user judge, deduped per module since `dkms status` lists one entry per kernel.
- Fix: the suggested remediation command for an unowned autostart/systemd `ExecStart` binary printed a bare `archcanary --allowlist-add=...`, which fails with "requires root" if copy-pasted as-is — `--allowlist-add` is a privileged action routed through the polkit-authorized root-helper, not something the script can do unprivileged. Now suggests the `pkexec`-wrapped root-helper command instead.
- Added: `--search-packages` checks package names against every loaded list without a full scan, and echoes a ready-to-copy `pacman -Rns` command on a match (never executes it) — prompted by the `org-cli` AUR takeover, where a name can be flagged now and legitimate again later if a trusted maintainer regains control.
- Fix: the pacman.log check flagged any historical match against the compromised-package list as a WARNING (exit 2, critical desktop notification) even if the package was removed years earlier — reported on the EOS forum, where a package removed in 2023 read identically to an active infection. A log hit for a package that's no longer installed now reports as a lower-severity historical note (exit 1) instead; packages still installed keep the full WARNING/exit-2 treatment.
- Added: `--doctor` detects a stale `~/.config/yay/init.lua` — same drift class as the earlier bash-completion check, but `install.sh` never overwrites an existing `init.lua` at all (see docs/my-setup.md, "yay 13.0 integration"), so a user who adopted archcanary's yay hooks before a later release changed them had no way to know their copy was behind. The header marker in `configs/yay-init.lua` now carries a version suffix (`(v2)`); `--doctor` checks for the *current* exact marker (`OK`), an older marker (`WARN`, with the exact `cp configs/yay-init.lua ~/.config/yay/init.lua` fix — reminding to merge in any of your own customizations first), or no marker at all (`OPT`, unchanged — not everyone uses yay). A full-file diff (like the bash-completion check) would have misfired here, since users are explicitly expected to hand-customize this file.
- Fix: the 45 packages added in v0.1.23 from the latest Arch Linux mailing list update landed in the wrong list. `package_list.txt`'s `--refresh` source is the official Arch Linux HedgeDoc note (external, not maintained here) — any user who runs `--refresh` gets that file fully overwritten from upstream, silently dropping hand-added entries the moment they refresh. `community_reports.txt` is the one whose `--refresh` source points back to this repo, so entries added there actually persist across every user's refresh. Moved all 45 there instead.

## v0.1.23 (2026-08-02)

- Added: 45 packages to `lists/package_list.txt` from the latest Arch Linux malicious-AUR-package mailing list update (a batch of `-bin` typosquat/impersonation packages, plus `proton-rtsp`). Cross-checked against every existing list first — no exact duplicates; `syncthingtray-qt6-bin` was already tracked via `lists/community_reports.txt` so it was left there rather than duplicated.
- Docs: the README's "Full flag reference" table was missing roughly half of `archcanary`'s actual flags — verbose/debug, log-file, the per-list override flags, date filters, notify/summary suppression, `--color`/`--format`, `--doctor=SECTION`, and every allowlist/extra-lists/aur-audit/audit-rules/lynis-config CLI verb added over the last several releases were implemented and documented in `--help` but never made it into the table. Filled in every missing row, cross-checked against the current `--help` output.
- Added: `--doctor` detects a stale user-level bash completion file silently shadowing a correct system-level one. Bash's dynamic completion loader checks the user completions directory (`~/.local/share/bash-completion/completions/`) before the system one, so it wins even when it's the wrong copy — a real, reported-live problem for anyone who ran a plain `./install.sh` once and later switched to `--system`/package installs without ever repeating the plain one, since neither install path touches the other's completion file and the two silently drift apart with no obvious symptom beyond "my new flag doesn't tab-complete." `--doctor` now compares the two files and warns with the exact fix (`bash install.sh`, which refreshes the user copy) when they differ; correctly stays silent when only one copy exists or both already match.
- Changed: the final `RESULT` banner said "WARNINGS - Review output above" even when every check that actually ran was clean and the *only* reason for a non-zero exit was an optional/root-only check being skipped (e.g. Lynis not installed) — reported live as confusingly alarming for a scan that found nothing. That specific case now shows "RESULT: CLEAN (INCOMPLETE) - No indicators found in the checks that ran; see below" instead. A real code-1 finding (e.g. bpftool's non-LSM-stealth warning) still shows "WARNINGS" — only the skip-only case changed. Exit code itself is unchanged (still 1 either way); `--format=json`'s `result` field is also unchanged, since it's a documented API another project consumes.
- Fix: `check_autostart`'s `.desktop` `Exec=` parsing didn't strip surrounding literal double quotes (allowed by the Desktop Entry Spec, and used by some installers — e.g. pCloud's — even when the path has no spaces to quote). Left quoted, the value was misclassified as an unresolvable bare name instead of an absolute path, and worse, was un-allowlistable: a real shell strips the quotes when the user types the exact suggested `--allowlist-add` command, so the stored (unquoted) value could never match the raw, still-quoted one compared at scan time. Reported live — the user could never get the suggested allowlist command to actually work. Quotes are now stripped before classification, display, and allowlist matching.
- Fix: `check_pkgbuild_caches`'s "ANSI-C hex/octal quoting" obfuscation pattern matched on a single `$'\x..'`/`$'\0..'` occurrence anywhere in a line — flagging the extremely common, completely legitimate `read -d $'\0'` idiom used for NUL-delimited `find -print0` iteration (reported live, a real `nvidia-utils-beta` PKGBUILD). Real obfuscation spells out a command a byte at a time via multiple chained escapes (e.g. `$'\x63\x75\x72\x6c'` for `curl`); a single delimiter byte has none of that shape. Now requires 3+ consecutive `\xHH`/`\NNN` escapes to match, closing the false positive while still catching genuine chained-escape obfuscation. No prior test coverage existed for this pattern at all — added regression tests for both the false-positive idiom and genuine obfuscation.

## v0.1.22 (2026-08-02)

- Fix: `packaging/PKGBUILD`'s embedded `autostart_allowlist.conf` template had drifted from `install.sh`'s — a pure package install (`makepkg -si`/AUR helper) seeded the old template (missing the full-path unowned-ExecStart-binary documentation and example added below) instead of the current one. Same recurring drift class as the `configs/audit-rules.conf` fix earlier this file — synced.
- Fix: `archcanary-gui`'s "Full scan" refused to run at all when root wasn't available, unlike the CLI (`archcanary --full` without sudo already skips root-only checks and reports INCOMPLETE). Full scan now falls back to the same non-root partial run the CLI does — a single root-only check (eBPF, bpftool, kmod, Lynis, pacman integrity) still blocks with a dialog, since those have no meaningful non-root version, but the bundle no longer refuses outright just because a few of its checks need root. Also fixed the blocking dialog itself: it collapsed two independent causes ("pkexec missing" vs. "root helper not installed") into one message that only ever suggested `./install.sh --system` — reported live: re-running that fixed nothing when the actual problem was `polkit` (which provides `pkexec`) not being installed at all. Now diagnoses and suggests the fix for whichever is actually missing.
- Removed: aurscan integration (the optional LLM-based PKGBUILD pre-install scanner, `manticore-projects/aurscan`) has been dropped entirely — `--doctor` detection, the GUI's "LLM settings" dialog and menu entry, the `configs/yay-init.lua` editor-gate references, and every README/docs/man-page/packaging mention. Prompted by aurscan's own AUR packages (`aurscan-manticore-bin-release-git`, `aurscan-manticore-release`) being deleted for a VCS packaging-guideline violation while AUR pushes are frozen during the ongoing malicious-adoption lockdown (see `SOURCES.md` §11) — with pushes disabled and no ETA to restore them, recommending an install method that's currently a dead end no longer made sense. archcanary's other detection layers (yay's own offline `init.lua` hooks, traur, and all of archcanary's own checks) are entirely unaffected — none of them ever depended on aurscan. `SOURCES.md`'s historical mailing-list entry documenting aurscan's original proposal (§3.3.4) is left untouched, same as `CHANGELOG.md`'s past entries — that's community history, not current integration status.

- Fix: `check_autostart` still flagged real Flatpak apps (Gearlever, MEGAsync, Eloquent all reported live) even after the earlier `$HOME/bin`/`$HOME/.local/bin` false-positive fix — Flatpak exports its own wrapper scripts into a fixed, distro-standardized location (`/var/lib/flatpak/exports/bin`, `$HOME/.local/share/flatpak/exports/bin`; `/etc/profile.d/flatpak-bindir.sh` adds both to `$PATH` on any Flatpak-enabled system) that the check never recognized as trusted, either via a resolved `$PATH` hit or the non-PATH libdir fallback search. Both dirs are now accepted the same way `$HOME/bin` already was, and the libdir search now follows symlinks (`find -L`) since Flatpak's exports are symlinks into the app's own sandboxed install dir — `-type f` alone never matched them.

- Added: `openconnect-sso` to `lists/community_reports.txt` — first confirmed package in a new, separate late-July 2026 AUR attack wave (malicious package adoption + follow-up commits, same Tor-exfil attacker signature as the June campaign but a distinct incident, still actively unfolding as of the last public update). See `SOURCES.md` §11 for the full writeup and sources — added there rather than as a new campaign-specific list since the wave's full scope isn't known yet.

- Changed: the per-check summary table and final RESULT banner no longer say "INFECTED" for heuristic/behavior-based checks (`check_autostart`, `check_systemd`, `check_bpftool`, `check_kmod`, `check_ldso`, the PKGBUILD obfuscation scan) — those show a softer "REVIEW"/"REVIEW NEEDED" instead. Reported live by two users whose entirely legitimate autostart entries (a personal script; AppImage-style apps like pCloud/Gearlever/MEGAsync) produced an "INFECTED... Follow incident response" verdict, which overstates certainty for a heuristic finding and risks unnecessary panic in an already-anxious post-incident community. Package-list/log-history matches and npm/bun/yarn/pnpm cache/package-integrity hits are genuine name/hash matches against known-malicious data, so those keep "INFECTED" — only the exit code's *display wording* changed, not its value (still 0/1/2, no script/CI-facing behavior changes). Also added a self-service hint to both `check_autostart` WARNING messages pointing at the exact `--allowlist-add=autostart:VALUE` command to mark a legitimate finding as known-good, since neither previously mentioned the allowlist mechanism existed at all.
- Fix: `check_autostart` had two real false-positive classes, both reported live. (1) An absolute `.desktop` `Exec=` path under `$HOME/bin` or `$HOME/.local/bin` (e.g. an LXQt-generated autostart entry pointing at a personal Conky launcher script) was flagged suspicious — the user-systemd-service branch already carried this exact exception, the `.desktop` Exec= branch never did. (2) A fully commented-out line in a shell RC (e.g. an old, disabled alias kept as a note) matching the download-and-execute pattern was flagged even though a `#`-prefixed line can never execute — mirrors the existing `Hidden=true`/`X-GNOME-Autostart-enabled=false` skip for `.desktop` entries. Added regression tests for both.
- Fix: bash tab-completion only ever fired for the installed `archcanary`/`canary` command names — running the script straight from a repo checkout (`./archcanary.sh --a<TAB>`) matched no completion spec at all (bash looks up a spec by the exact literal first word typed), silently falling back to default filename completion, i.e. nothing. Also registered for `archcanary.sh`/`./archcanary.sh`.
- Fix: `--allowlist-add=autostart:VALUE`/`--allowlist-remove=autostart:VALUE` rejected any full-path value (e.g. `/usr/bin/eos-update-notifier`) with `Error: invalid allowlist value` — the value regex required the first character to be alphanumeric and never allowed `/` at all, so the full-path matching added for the unowned-ExecStart-binary finding earlier the same day was actually unreachable from the CLI (and from the GUI's pkexec root-helper, `lib/archcanary-root-helper`, which duplicates the same regex as the real polkit privilege boundary and had the identical bug). Both now allow `/` while still rejecting whitespace, `#`, `:`, and other unsafe characters. Neither validation path had any test coverage before this — added regression tests for both the full-path and bare-name cases, plus confirming space/colon values are still rejected.
- Fix: bash tab-completion (`configs/archcanary-completion.bash`) hadn't been updated since it was first added in v0.1.20 — the 14 CLI verbs added across PRs #122-#124 (`--allowlist-*`, `--extra-lists-*`, `--aur-audit-*`, `--audit-rules-*`, `--lynis-config-*`) and `--format=` from PR #122 were all invisible to tab-completion. Added all of them, plus value-completion for `--allowlist-list=`/`--allowlist-add=`/`--allowlist-remove=` (the four allowlist names) and `--format=` (`text`/`json`), and file-path completion for `--extra-lists-add=`/`--extra-lists-remove=`.
- Added: `check_autostart`'s "user systemd service with unowned ExecStart binary" finding can now be allowlisted — it reuses the existing autostart allowlist (`/etc/archcanary/autostart_allowlist.conf`, `AUTOSTART_ALLOWLIST`), matched against the ExecStart binary's exact, full path (not its basename — a basename-only match would let an unrelated binary anywhere on disk slip through just by sharing a name with something legitimately allowlisted). Previously this branch had no escape hatch at all, unlike the `.desktop` Exec= branch right above it in the same check. Found via an EndeavourOS report: `eos-update-notifier` ships its systemd user unit through `/etc/skel`, which gets copied verbatim into `~/.config/systemd/user/` at account creation — pacman never tracks that copy even though `/usr/bin/eos-update-notifier` itself is a normal pacman-owned file.
- Added: `CONTRIBUTING.md`, a GitHub issue form (`.github/ISSUE_TEMPLATE/report-package.yml`), and a PR template (`.github/PULL_REQUEST_TEMPLATE.md`) for reporting a malicious/suspicious AUR package into `lists/community_reports.txt` — either via a low-friction form (no git needed) or a direct PR, both asking for the same evidence link so reports can be reviewed without back-and-forth.
- Changed: reordered README.md so Quick Start comes right after the intro instead of after a 10-row dependency table and an architecture explainer — the simple "just run archcanary" path now comes before the deeper-dive material (Projects Used, Detection Layers), which moved down. The full `--check-*` flag reference table is now collapsed behind a `<details>` toggle, with a one-line summary staying visible. No content removed, only reordered/collapsed.
- Added: a Quick Start example showing `archcanary --refresh`'s "Lists loaded" banner (per-list counts plus the `+N`/`-N` delta since the last run), alongside the existing plain-scan check-summary example.
- Fix: the AUR `PKGBUILD` never installed `configs/audit-rules.conf` — a pure package install (`makepkg -si` or an AUR helper) had no template at `/usr/lib/archcanary/audit-rules.conf`, so `archcanary-gui`'s Edit config → Audit rules always showed "No rules found. Run ./install.sh --system to seed the template." even though the user had installed via the package, not `install.sh`. Same root cause as PR #88 (missing config templates in `package()`), just one file that got missed back then. `package()` now installs the template, and `archcanary.install`'s `post_install()` seeds the real `/etc/audit/rules.d/30-archcanary.rules` when auditd is present, mirroring `install.sh`'s existing runtime check exactly (and the same pattern already used for Lynis's `custom.prf`). Packaging-metadata-only fix — `pkgrel` bump, no new tag.

## v0.1.21 (2026-08-01)

- Added: `--check-list-overlap` notes custom list (`extra_lists.conf`/`--extra-list`) entries already covered by an official list (`package_list.txt`, CHAOS RAT, Russian Spam, Community Reports, aur-audit black/red) — grouped by file, each with a ready-to-run `sed` command to remove exactly those entries, since the official list is authoritative. A note, not a warning: always shows "clean" in the check summary and never affects the exit status, and not included in `--full`. The same note prints twice — once in its own section, once again right after the final RESULT banner — so it's visible without scrolling back up. Also reachable from the GUI: `archcanary-gui` → Edit config → List overlap check, which runs it and shows just its own report (with the live count in the window title) rather than a full scan.
- Added: Community Reports (`community_reports.txt`) — a new supplementary list for individually-reported AUR packages that don't (yet) belong to a documented campaign, refreshed the same way as the CHAOS RAT/Russian Spam lists. Hits are annotated `[community report]`. No fixed scope or end date, unlike the campaign-specific lists — an ongoing collection point maintained directly in this repo.
- Fixed: a package list file (or any other file archcanary reads line-by-line: `--extra-list` sources, PKGBUILDs, `.desktop` files, shell RC files) whose last line has no trailing newline silently lost that last line entirely — classic `while read` gotcha. Found via a real 42-entry custom list whose last package name was silently never matched against. Fixed in every affected reader (12 in total); the ones reading from command output (`pacman.log`, `lsmod`, etc.) were already safe and untouched.

## v0.1.20 (2026-08-01)

- Added: `--refresh` now also syncs the black/red package lists from the third-party [aur-audit.wtako.net](https://wtako.net/services/aur-audit) service (continuous community AUR scan feed, free/unauthenticated API). Hits merge into the existing infected-package check, annotated `[aur-audit: black]`/`[aur-audit: red]`. Yellow (qualitative/minor) findings are not synced. Purely additive — no new dependency, no network call outside `--refresh`, no CLI overrides.
- Added: new `AURPreInstall` yay hook in `configs/yay-init.lua` checks the about-to-build package against the synced aur-audit black/red lists — aborts on black, warns on red. Gives pre-build protection against known-bad AUR packages without requiring aurscan/an LLM. No new systemd unit: the existing weekly/on-boot `archcanary.timer` already keeps the lists fresh via `--refresh`.
- Added: bash tab-completion (`configs/archcanary-completion.bash`), installed by both `install.sh` and the AUR package into the standard `bash-completion` completions directory — no `.bashrc` edits needed. Also registers a `canary` completion alongside it (as a symlink) for anyone who adds their own `alias canary=archcanary`.
- Added: the "Lists loaded" banner now shows a `+N`/`-N` delta next to each list's package count, comparing against the previous run's count persisted to `~/.config/archcanary/.list_counts` (keyed by the list's resolved path, merged rather than overwritten, so a one-off `--package-list`/test run can't clobber the real baseline) — makes a growing/shrinking threat-intel feed (e.g. aur-audit red after `--refresh`) visible at a glance instead of requiring a manual before/after comparison.
- Added: each `extra_lists.conf`/`--extra-list` source now gets its own line in the "Lists loaded" banner (basename + count + independent delta) instead of being rolled into one generic "extra lists" total — lets a user with multiple custom lists see which one actually grew or shrank.
- Added: `--no-aur-audit` flag / `AUR_AUDIT_ENABLE=false` env var to skip the aur-audit.wtako.net feed on `--refresh` while leaving previously fetched black/red lists on disk untouched. Persists across runs via `~/.config/archcanary/env` — read as plain data (never sourced as shell), since the pkexec-elevated root scan resolves that same path under the invoking user's own `$HOME` and sourcing it would be a local privilege escalation. Also toggleable from `archcanary-gui`'s top-level **Scan settings** menu row, which shows live `ON`/`OFF` state right in the row label.

## v0.1.19 (2026-07-25)

- Fix: the AUR package `aurscan-manticore-git` no longer exists — upstream split it into `aurscan-manticore-release-git` (source build) and `aurscan-manticore-bin-release-git` (prebuilt binary). Updated every install command/optdepend pointing at the old name, including the `PKGBUILD`'s own `optdepends="aurscan: ..."`, which never matched anyway since no AUR package is literally named `aurscan`.

## v0.1.18 (2026-07-23)

- Fix: `lists/at_risk_accounts.json`, `lists/iocs.txt`, and `lists/malicious_russian_spam_packages.txt` had been frozen since the `aur-malware-check` rename and never resynced against upstream `lenucksi/aur-malware-check`. Added 6 wave-2 attacker accounts, 2 missing russian-spam packages (`obd-auto-doctor`, `peksystray`), the sudo-password-grabber IOC, the `ansi-colors` companion-package note, and a "Malicious Git Commits" section. Also fixed a stale `ioctl.fail` source URL in `iocs.txt`/`SOURCES.md` that pointed at a nonexistent slug. These three files are reference/analyst data only — never read by `archcanary.sh` at scan time, unlike the four detection lists that are.

## v0.1.17 (2026-07-20)

- Change: `--doctor` now detects whether aurscan's own yay/paru pre-build hooks are actually wired up, not just whether the `aurscan` binary is installed — greps for aurscan's managed marker in `~/.config/yay/init.lua` and `paru.conf`, shown only when the respective AUR helper is present, with the exact `aurscan --install-yay-hook`/`--install-paru-hook` fix command surfaced. Added `paru` as a recognized `--doctor=SECTION` alias. Also fixed `_opt_item` silently dropping its fix-hint for every optional check that passed one, and switched the "archcanary's own hooks" check from bare file existence to an actual content check so it can no longer report clean when the hooks were stripped out by hand.
- Fix: the AUR `PKGBUILD` only ever seeded `dkms_allowlist.conf` — a plain `pacman -U` package install was missing `systemd_allowlist.conf`, `bpftool_allowlist.conf`, `autostart_allowlist.conf`, `lynis-custom.prf`, and the man page entirely, so a package-only install still required a manual `install.sh --system` run afterward to be complete. All five are now included in `package()`.

## v0.1.16 (2026-07-19)

- Change: `install.sh --system` no longer auto-enables the systemd timers (`archcanary.timer`, `archcanary.path`, `archcanary-user.timer`, `archcanary-notify.path`) — it now installs the units and prints the same `systemctl enable --now` commands the pacman/AUR package's `post_install` prints, so both install paths require the same explicit, manual activation step instead of one silently enabling behind the user's back.

## v0.1.15 (2026-07-19)

- Fix: `--doctor`'s "User install" section reported `[MISS]` for `~/.local/bin/archcanary` and `~/.local/bin/archcanary-gui` on every pacman/AUR install. `system_installed` detection only checked `/usr/local/bin/archcanary` (the manual `install.sh --system` path), never `/usr/bin/archcanary` (where the PKGBUILD actually installs it) — so package installs always failed the check and got flagged for per-user copies that were never expected to exist alongside a system-wide package.

## v0.1.14 (2026-07-18)

- Fix: `archcanary.service` (root system scan, triggered by `archcanary.timer` on boot/weekly) failed on every fresh `--system`/AUR install with `ERROR: Malicious npm package list not found`. The repo-layout reorg (#40) had updated `archcanary.sh`'s bundled-list fallback to expect a `lists/` subdir, but `install.sh --system` and the AUR `PKGBUILD` both deploy the lists flat into `/usr/lib/archcanary/`, alongside the script — root's `$HOME` is deliberately never seeded, so the root scan had no working fallback and exited 1 immediately. `_bundled_list_path()` now checks the flat (installed) layout first, then the `lists/` (repo checkout) layout.

## v0.1.13 (2026-07-16)

- Fix: `archcanary -V`/`--version` and the GUI's About dialog reported a stale version after upgrading — `archcanary.sh` carried its own hardcoded `SCRIPT_VERSION`, separate from `version.txt`, and the v0.1.12 bump only updated `version.txt`. `install.sh` now stamps the real version from `version.txt` into every installed copy of `archcanary.sh` (user bin, system bin, and `/usr/lib/archcanary`) at install time, making `version.txt` the actual single source of truth; running the script unstamped straight from a git checkout falls back to reading the sibling `version.txt` directly. The GUI's About dialog now calls `archcanary --version` instead of grepping the script's source for `SCRIPT_VERSION=`.

## v0.1.12 (2026-07-13)

- Fix: `sudo archcanary ...` and GUI root scans (pkexec) left their log file — and, via the same `_chown_to_invoker` gap, the package-list cache and config-editor writes — owned by root inside the invoking user's `~/.cache`/`~/.config`. `_chown_to_invoker` only checked `SUDO_USER`, so the pkexec path (`PKEXEC_UID` only) was a silent no-op, and `LOG_FILE` itself was never passed through it at all. Also fixed: the chown only reset owner, not group (`chown user:` now resets both), and the `PKEXEC_UID` branch resolves to a login name via `getent passwd` first since `chown` rejects a bare numeric `UID:` spec outright (`invalid spec`). Users upgrading should run `sudo chown $USER:$USER ~/.cache/archcanary/*.log` once to clean up logs left behind by earlier versions.

## v0.1.11 (2026-07-12)

- New: **autostart allowlist** (`/etc/archcanary/autostart_allowlist.conf`) — mirrors the DKMS/systemd/bpftool allowlists for `check_autostart` entries that can't be auto-resolved. `check_autostart` also gained a non-PATH fallback (searches `/usr/lib`, `/usr/libexec`) before flagging a bare `Exec=` name as suspicious, fixing false positives for package-private helper binaries (e.g. `zeitgeist-datahub`) that never sit on `$PATH`.
- Fix: glob-metacharacter injection in the new non-PATH fallback — an autostart entry like `Exec=*` could match an arbitrary executable and bypass the suspicious-autostart check entirely; `*`/`?`/`[`/`]`/`\` are now escaped before reaching `find -name`.
- Fix: `notify-send` failing silently under Openbox terminals and root scans (`sudo archcanary --full`) — both lack `$DBUS_SESSION_BUS_ADDRESS`, so notify-send fell back to `dbus-launch --autolaunch`, which errors out instead of showing the alert. Falls back to the well-known `/run/user/<uid>/bus` socket for the non-root case, and resolves the invoking user via `SUDO_USER` for the root case.
- Fix: curl/wget pipe-to-shell autostart/RC pattern now matches across newlines.
- Docs: fixed several stale/duplicated explanations found during a documentation precision pass — README's detection-layers diagram was missing the `traur` pacman hook layer; `docs/overview.md`'s lifecycle diagram had the `PostInstall` yay hook in the wrong sequence position; README and `my-setup.md` both claimed traur has "5 weighted categories" (verified against the installed binary: it's 4); README's detection-layers diagram and Projects-Used table were redundant copies of `overview.md`/`my-setup.md`'s versions and are now trimmed to short pointers; `docs/systemd.md`'s "Why the split?" section repeated its own "Model" section almost verbatim.

## v0.1.10 (2026-07-03)

- New: `--check-pkginteg` — verifies installed file checksums via `pacman -Qkk`, filtering out backup-file and `/factory/` noise to surface real SHA256 mismatches on pacman-managed files. Included in `--full`; runs as root (a regular user silently skips unreadable files). GUI row moved to Utilities as "Pacman integrity".
- New: **systemd unit allowlist** (`/etc/archcanary/systemd_allowlist.conf`) — mirrors the DKMS allowlist so a legitimate custom service (not pacman-owned, `Restart=always`, non-standard binary path) can be marked known-good instead of always flagged as persistence. Drop-in overrides resolve to their parent unit.
- New: **bpftool eBPF-loader allowlist** (`/etc/archcanary/bpftool_allowlist.conf`) — same escape hatch for `check_bpftool`, for legitimate non-pacman VPN/security tools that load LSM eBPF programs. `_systemd_allowlisted` generalized to `_allowlist_contains` and reused by the DKMS lookup too.
- New: GUI menu consolidation — the DKMS/systemd/bpftool allowlist editors merge into one "Manage allowlists" picker, and the audit-rules/Lynis-config/extra-lists editors merge into one "Edit config" picker, capping menu growth as more allowlists are added.
- New: `version.txt` is now the single source of truth for the version string; `install.sh` stamps it into the man page at install time.
- Fix: `check_bpftool` false positives — warnings now name the actual unknown loader processes inline, systemd child services (not just PID 1) are recognized as known-good loaders, and any remaining unknown loader whose binary resolves to a pacman-owned package is downgraded to INFO with the package name shown.
- Fix: infected-package extraction was scanning every `- ` bullet line across all check sections, so a non-package finding (e.g. a flagged systemd unit) could be fed into `yay -R` as if it were an AUR package. Now scoped to the package-check section only.
- Fix: closing "Manage allowlists" or "Edit config" without making a selection (Close button or window-close) killed the whole GUI instead of returning to the menu — a bare `return` after a failed `yad` call inherited its exit status, which `set -e` treated as fatal.
- Fix: audit-rules editor — clearing all text and saving no longer truncates the rules file to zero bytes (guarded on non-empty save); legacy `30-archcanary.conf` is migrated to `.rules` on edit instead of shadowing it.
- Fix: GUI audit-rules path realigned with the installer's `.conf` → `.rules` rename.
- Fix: uninstall no longer removes user data — `~/.config/archcanary`, `/etc/archcanary`, and `/var/lib/archcanary` are preserved across reinstall/removal.
- Fix: `--doctor` always shows the Dependencies section (previously hidden when all deps were OK, which read as "not checked"); its `--system` install hint no longer lands after a shell comment where it would be silently dropped on copy-paste; `sudo` removed from the `install.sh` fix hint since the installer blocks root execution and calls `sudo` internally.
- Fix: GUI "About" row status indexing corrected after the Pacman integrity row shifted indices.
- Docs: restored `--package-list`/`--extra-list` rows dropped from the README checks table.
- Chore: Lynis plugin support was added and then removed again after confirming Lynis's built-in malware-scanner check is hardcoded to a fixed tool list and cannot be extended via plugins — net no externally visible change.

## v0.1.9 (2026-06-23)

- New: **auditd post-build snapshot** — both scan services (`archcanary.service` and `archcanary-onchange.service`) now append `aur_build` audit events to `last-scan.log` after each run via `ExecStartPre`/`ExecStartPost`. Uses the mtime of the previous log as the implicit "last checked" timestamp; no extra state file needed. Bridges the gap between static pre-build PKGBUILD analysis and runtime kernel audit events.
- New: `--start-date`/`--end-date` CLI flags for date-window filtering of pacman log history.
- New: `--check-pkgbuild` detects two additional obfuscation patterns: ANSI-C hex/octal escape sequences (`$'\x62\x61\x73\x68'`) and `rev`/`tr`-based string reversal piped to shell.
- New: `--doctor` includes a traur pacman hook sub-check.
- Fix: auditd rules file was installed as `30-archcanary.conf` — `augenrules` silently ignores files without a `.rules` extension, leaving auditd with no active rules. Renamed to `30-archcanary.rules`; `install.sh` and `uninstall` now also clean up legacy `.conf` copies.
- Fix: `systemctl restart auditd` replaced with `augenrules --load` — Arch configures auditd with `RefuseManualStart=yes`; the restart always failed silently.
- Fix: `--run-lynis` was wired up but absent from `--help` output; documented with a note that it is intentionally excluded from `--full` (avoids a 2-minute Lynis run in automated scans). Lynis plugin concept removed — Lynis's built-in malware scanner check is hardcoded to known tools and cannot be extended via plugins.
- Fix: GUI suggests `archcanary-gui --no-gui` in the sudo hint when invoked via the GUI wrapper.
- Fix: man page SEE ALSO updated — added `auditd(8)`, `bpftool(8)`, `yay(8)`, `traur(1)`; removed stale `archcanary-gui(1)` entry.
- Chore: `packaging/` removed during beta period.
- Chore: `notepad-bin` dropped from the infected package list.
- Docs: all aurscan references updated to the upstream AUR package `aurscan-manticore-git`; AUR install commands added.

## v0.1.7 (2026-06-22)

- New: **Lynis integration** — two GUI rows: *Lynis hardening report* reads the last `/var/log/lynis-report.dat` (hardening index, warnings, scan date); *Run Lynis audit* executes `lynis audit system` via pkexec and streams output.
- New: **auditd rules editor** — GUI row (Utilities → Edit audit rules) visible when auditd is installed. Ships a default ruleset covering privilege escalation, pacman/AUR builds, kernel modules, systemd units, cron, and SSH config. Editable in-GUI; saves via pkexec and restarts auditd.
- New: `install.sh --system` seeds `/etc/audit/rules.d/30-archcanary.rules` from the bundled template when auditd is installed and the file has no rules.
- Fix: Lynis output ANSI cursor-movement codes (`ESC[2C`, `ESC[30C`) stripped before display in yad — `--no-colors` suppresses color SGR sequences but not cursor movement.
- Fix: non-ASCII Unicode block characters (`▆` etc.) stripped from Lynis output for yad text-info compatibility.
- Fix: `NEEDS_ROOT[16]` corrected to `true` — `/var/log/lynis-report.dat` is always mode 600; the non-root designation caused spurious WARNINGS in every full scan.
- Fix: `--check-lynis` added to root-helper allowlist.
- Fix: polkit wait message scoped to idx 0 only — other root checks no longer show the network-fetch warning.
- Fix: busy indicator added to Run Lynis audit output window.
- Fix: `*` bullet used in `check_lynis` warnings list (replaces `•` for monospace font compatibility).

## v0.1.6 (2026-06-21)

- Fix: the GUI root-scan (pkexec) output window now opens immediately when you
  click Run, eliminating the blank-screen gap that made the first full scan
  look like a crash. The window prints an "Authenticate in the polkit dialog to
  continue..." prompt up front, then a `============` separator before the live
  scan output begins.
- Fix: restored polkit dialog focus handling — a short settle delay plus an
  xdotool loop activates the "Authenticate" window on click-to-focus WMs like
  Openbox, where new windows don't auto-focus. xdotool is optional; focus
  degrades silently if it is absent. (This reverts a regression that had
  dropped the focus hack in favour of a background-pkexec approach, which
  reintroduced the blank-screen problem.)
- Fix: on auth cancel or failure, the output window is closed cleanly before
  the error dialog instead of being left empty.
- Docs: clarified that aurscan PKGBUILD scanning is wired symmetrically for
  both paru and yay; noted `aurscan --install-paru-hook` for paru users.

## v0.1.5 (2026-06-21)

- New: Arch packaging — `packaging/` directory with `PKGBUILD`, `.SRCINFO`, and
  install scriptlet; the tool is now installable from a source tarball / AUR.
- New: focused mode suppresses the campaign header and default checks when the
  GUI runs a single targeted check, so each output window shows only its check.
- New: first full scan per GUI session auto-refreshes the package list, then
  subsequent scans skip the network fetch for speed.
- New: `--check-bpftool` expanded with perf-hook and net-attachment sub-checks.
- Fix: pkexec output streaming reworked — wait for pkexec before inspecting
  output, stream via `tmpout` + `tail -f` (replacing `tail --pid`), and guard
  the done-marker `printf` against SIGPIPE on early window close.
- Fix: `--check-kmod` DKMS false positives and a `set -e` crash risk.
- Fix: `install.sh --system` patches the user service `ExecStart` to
  `/usr/local/bin`; `/usr/local/bin` is skipped in the autostart check.
- Refactor: removed the deep-analyse / claude CLI integration from the GUI.

## v0.1.4 (2026-06-20)

- Fix: `archcanary-gui` now rejects `sudo`/root invocation with a clear error;
  root checks are handled via pkexec (polkit). `--no-gui` mode is exempt since
  it runs a terminal scan where root is legitimate.
- Fix: root output window (pkexec scans) no longer auto-closes when the scan
  finishes; it stays open until the user clicks Close. Implemented via a named
  FIFO — the write end is held open until `wait` returns, preventing yad from
  seeing EOF prematurely.
- Fix: closing the root output window no longer exits the entire GUI. Previous
  `sleep infinity` approach blocked bash indefinitely; replaced with FIFO.
- New: `--no-summary` flag suppresses the check summary table at the end of a
  scan. Passed automatically by the GUI (the status column already shows
  per-check results). CLI and `--no-gui` are unaffected.
- Refactor: removed standalone "Refresh package list" action from the GUI.
  Users always start with "Refresh + full scan"; a bare refresh row had no
  real use case.
- Fix: `--doctor` user-install section now correctly shows/hides `~/.local/bin`
  entries based on whether `/usr/local/bin/archcanary` exists, not whether the
  system lib dir exists (which persists after switching to a user install).
- Fix: `--doctor` dependencies section is hidden when all four deps are present;
  still shown when any is missing or when `--doctor=deps` is used.
- Fix: `install.sh` now warns to run `hash -r` (or open a new terminal) when
  switching between user and system installs, since bash caches the old path.
- Docs: clarified `--doctor` labels — "system scanner copy" → "scanner script
  (/usr/lib/archcanary)", "root-helper (pkexec)" → "root helper (enables root
  checks in GUI)", "polkit policy" → "polkit policy (authorizes the root
  helper)", "aurscan wrapper" → "aurscan (pre-install PKGBUILD scanner)",
  "traur (heuristic scanner)" → "traur (pre-install behavioral scanner)",
  "yay init.lua hooks" → "yay hooks (auto-scan on yay install)", "desktop
  notifier (watches last-scan.log)" → "desktop notifier (alerts on new scan
  results)".
- New: `archcanary-gui --help` documents `--no-gui` usage, sudo rules, and
  refers to `archcanary --help` for the full flag list.

## v0.1.3 (2026-06-18)

- New: `--extra-list=PATH_OR_URL` — load an additional package list for a
  one-shot scan; accepts a file path or a raw https:// URL. Repeatable.
- New: `~/.config/archcanary/extra_lists.conf` — persistent subscription
  file, one path or URL per line, loaded automatically on every run. URL
  entries are cached locally and re-fetched on `--refresh`. Seeded with a
  commented template on first run.
- New: `--refresh` now updates all supplementary lists (`malicious_npm_
  packages.txt`, `chaos_rat_packages.txt`, `malicious_russian_spam_
  packages.txt`) from the repo's raw GitHub URLs in addition to the main
  HedgeDoc AUR list. Non-fatal on failure. All lists now live in
  `~/.config/archcanary/` and are seeded from the bundled copy on first run.

## v0.1.2 (2026-06-18)

- New: **Russian Spam Campaign list** (`malicious_russian_spam_packages.txt`, 83
  entries, Sid Karunaratne 2026-06-14) wired into the scanner as a dedicated
  detection layer alongside the CHAOS RAT list. Packages injecting spam into
  `~/.bashrc` / `~/.zshrc`. Shown in the scan header; accessible via
  `--russian-spam-list=PATH`. Copied to `/usr/lib/archcanary/` by `--system`
  install so the root scan finds it.
- Fix: `--doctor` user-install check was looking for `~/.local/bin/archcanary.sh`
  (always MISS); now checks `~/.local/bin/archcanary`.
- Fix: GUI candidate lookup used `command -v archcanary.sh` (never matched);
  replaced with `/usr/lib/archcanary/archcanary.sh` as a third fallback so the
  GUI finds the system install when run outside the repo.
- Fix: all user-facing text, docs, and hints updated from `archcanary.sh` →
  `archcanary` to match the installed binary name (no `.sh` extension).

## v0.1.1 (2026-06-18) — post-release fix

- Fix: `--doctor` treated missing aurscan, traur, `alias yay=syay`, and yay
  `init.lua` as failures (`[MISS]`), contributing to the fail count and driving
  the NEXT STEP pointer toward installing AI tools. These are optional addons —
  archcanary works fully without any LLM or AI tooling. They now show `[OPT ]`
  (cyan), never set fail, and never block the next-step pointer. A system
  without any AI layer gets a clean `--doctor` summary.

## v0.1.0 (2026-06-18) — first tagged release

### Project
- Renamed from `aur-malware-check` to **archcanary**. The tool had grown into a
  multi-layer Arch system security stack; the old name no longer reflected its
  scope. All files, strings, and system paths updated.
- Complete README rewrite: BETA notice, rename history, projects-used table,
  detection layer diagram, checks reference, screenshots (GUI, scan output, LLM
  settings dialog).
- First git tag `v0.1.0`.

### GUI (`archcanary-gui.sh`)
- New: **LLM settings dialog** — Utilities → LLM settings. Configures aurscan's
  LLM backend (backend, endpoint URL, fallback URL, model, timeout) and writes
  `~/.config/aurscan/env`. Includes a looping Model guide with local model
  size/quality table and Ollama `num_ctx` warning.
- Fix: `aurscan_settings()` silently exited under `set -euo pipefail`. Two bugs:
  `_env_get` grep exiting non-zero on a missing env file propagated through
  `pipefail` and killed the function before yad opened; and `result=$(yad ...)`
  triggered `set -e` when yay exited non-zero (cancel / model guide). Fixed with
  `|| true` on the pipeline and the `&& rc=0 || rc=$?` capture pattern.
- Fix: `traur` status column cleared — it opens its own output window so the
  `?` marker added no information.
- Fix: duplicate `archcanary.sh` candidate in the startup script-finder (left
  over from the rename); now also searches for `archcanary` (no extension) in PATH.
- Detect aurscan with `command -v aurscan`; LLM settings item only shown when
  aurscan is installed.

### Install / system
- Installed binaries are now named `archcanary` and `archcanary-gui` (no `.sh`
  extension). Uninstall and the user systemd service updated to match.
- Fix: `archcanary-root-helper` had a hardcoded
  `/usr/lib/aur-malware-check/aur-malware-check.sh` path left from the rename.
  Updated to `/usr/lib/archcanary/archcanary.sh`.
- Fix: root-helper and GUI dialogs told users to run `sudo ./install.sh --system`.
  `install.sh` must never be run as root — it calls sudo internally. Removed
  `sudo` from all user-facing install prompts.

## 3.0 (2026-06-16)
- New: `archcanary_py/` — Python 3.14+ port of `archcanary.sh`, stdlib only
- All 6 checks preserved, `--merge` mode, compressed log support (gzip/xz/bz2/zstd)
- 75 unit tests, `unittest` + `unittest.mock`, laufen ohne Arch-System
- `developing.md` — coding conventions, `README.md` — use-case map
- Bash scripts remain at 2.3.x for legacy use

## 2.12.1 (2026-06-18) — personal fork
- Fix: the desktop notifier (`archcanary-notify.path`) wedged into a permanent `failed` (`start-limit-hit`) state, silently disabling detection alerts. The path unit used `PathModified=`, which fires on **every write** to `last-scan.log`; since the scan streams that file line-by-line via `tee`, a single scan triggered the oneshot notifier dozens of times in seconds and tripped systemd's default start limit. Switched to `PathChanged=` (fires once when the writer closes the file) and set `StartLimitIntervalSec=0` on both the `.path` and `.service` so a transient burst can never permanently wedge the watcher. Recover an already-failed unit with `systemctl --user reset-failed archcanary-notify.path && systemctl --user restart archcanary-notify.path` (or re-run `install.sh --system`). Surfaced by the new `--doctor` systemd state check.

## 2.12.0 (2026-06-18) — personal fork
- Change: `--doctor` Automation (systemd) section now checks **real unit state**, not just whether the unit file exists. It queries `systemctl is-enabled`/`is-active` (no root needed) for the four units the installer enables — system `archcanary.timer` + `.path`, and **user** `archcanary-user.timer` + `notify.path` (the user scan timer was previously not checked at all) — and gives a **state-appropriate fix**: not installed → re-run the installer; present but disabled → `systemctl enable --now`; enabled but failed/inactive → `systemctl restart` + a `status` hint. The user bus being unavailable (over SSH/sudo) is reported, not flagged as missing.
- New: a third status marker **`[WARN]`** (yellow) for elements that are present but not functioning (e.g. a unit installed-but-disabled or enabled-but-failed), distinct from `[MISS]` (red, absent) and `[ OK ]` (green). WARN and MISS both feed the next-step pointer and set a non-zero exit.

## 2.11.1 (2026-06-18) — personal fork
- Fix: `--doctor` section selection is now forgiving about input. Sections can be **space-separated** (`--doctor user system`) as well as comma-separated, and a stray space in a comma list (`--doctor=user, system`, which the shell splits into two arguments) no longer silently drops the trailing section. **Tool names** now map to their section too — `aurscan`/`syay`/`traur`/`yay` → `external`; `yad`/`bpftool`/`pkexec`/etc. → `deps` — so `--doctor=aurscan` works. The header shows the resolved sections (deduplicated, in order) instead of the raw input.

## 2.11.0 (2026-06-18) — personal fork
- New: `--doctor=SECTION[,...]` — check only the named section(s) instead of the whole stack. Sections (in install order): `platform`, `deps`, `user`, `system`, `systemd`, `external`; comma-separate for several (`--doctor=user,system`). Filtered runs show **drill-down detail** per item — resolved path, version, and package for dependencies; the checked path for files; the resolved alias/binary for the external layer.
- New: **next-step pointer** — when something is missing, `--doctor` now names the first unmet prerequisite (sections run in install order) and prints the single command to run next, so the check reads start-to-finish: fix it, re-run, advance. Bare `--doctor` is unchanged (compact, all sections). Unknown section names exit 2; missing elements exit 1; all-present exits 0. The interactive click-to-fix version is left for the GUI phase.

## 2.10.0 (2026-06-18) — personal fork
- New: `--doctor` — a standalone setup health check that reports the install/config status of every element of the stack (dependencies, user install, system/root install, systemd automation, and the pre-install layer: aurscan/syay, the `yay=syay` alias, traur, yay `init.lua` hooks). Each missing item prints the exact command to fix it. It runs before the scan machinery (no log tee, no list loading) so it never errors on the very state it reports, and it auto-detects the platform (distro, AUR helpers present, `mhwd`). Exit 0 = all present, 1 = something missing. The alias check reads the resolved interactive alias rather than grepping a fixed file, so it works regardless of which file defines it or whether the value is quoted. The GUI will surface these fix commands as copyable / open-terminal actions (it never auto-runs installs).

## 2.9.9 (2026-06-17) — personal fork
- Change: the DKMS allowlist is now a **single system-wide file** at `/etc/archcanary/dkms_allowlist.conf`. After the system/user scan split the kmod audit only runs as root, so a per-user `~/.config` copy was vestigial and confusing (two files, only `/etc` authoritative). The script now reads only `/etc` (override with `DKMS_ALLOWLIST_FILE` for tests); `install.sh --system` seeds it (migrating any existing `~/.config` entries, then removing that per-user copy); base `install.sh` no longer creates a per-user allowlist; and the GUI **Edit DKMS allowlist** button now edits `/etc` and saves it back via pkexec. Edit it with the GUI button or `sudoedit /etc/archcanary/dkms_allowlist.conf`.

## 2.9.8 (2026-06-17) — personal fork
- Fix: the GUI no longer marks **every** check ❌ when a full scan finds one problem. `_propagate_full_scan` used to stamp the single overall verdict onto all rows, so one `INFECTED` check (e.g. an unallowlisted DKMS module) lit up the whole list. It now parses each check's own `--- [N] ---` section in the scan output and sets that row from its own result (WARNING/INFECTED → ❌, Skipped/needs-root → ?, otherwise ✅) — a finding points at the check that found it.

## 2.9.7 (2026-06-17) — personal fork
- Change: automated scanning is split by context so neither half false-positives. The **root system** timer now runs only the system-level checks (`--check-systemd/--check-ebpf/--check-bpftool/--check-ldso/--check-kmod` + the always-on package/log checks); a new **user** timer (`archcanary-user.{service,timer}`) runs the user-level checks (`--check-npm-cache/--check-bun-cache/--check-yarn-cache/--check-pnpm-cache/--check-pkgbuild/--check-autostart`) as your user, so they scan your real `~/.cache`/`~/.config` instead of `/root`. Fixes the root scan flagging root's own `/root/.config/autostart` session relics as a false `RESULT: INFECTED`. The user scan notifies itself (runs in your session); the root scan still uses the path-watched notifier. `install.sh --system` installs and enables both; `systemd.md` updated.
- Fix: the DKMS allowlist loader used `[[ -f ]]` and aborted the whole scan (`Permission denied`, exit 1, under `set -e`) when `/etc/archcanary/dkms_allowlist.conf` existed but was not readable. It now tests `[[ -r ]]` and skips unreadable files, and `install.sh --system` installs the system allowlist mode `644` (the user-level scan reads it too, even if your `~/.config` copy is `600`).

## 2.9.6 (2026-06-17) — personal fork
- Fix: the root **system** scan flagged allowlisted DKMS modules (e.g. `tuxedo-drivers`) as "untracked source" → false `RESULT: INFECTED`. The DKMS allowlist lived only in the user's `~/.config`, which the root service (`HOME=/root`) can't see. The script now also reads a **system-wide** `/etc/archcanary/dkms_allowlist.conf` (merged with the per-user file), and `install.sh --system` seeds it from your user allowlist. Re-run `install.sh --system` (or edit `/etc/...`) after changing the allowlist.

## 2.9.5 (2026-06-17) — personal fork
- Fix: the root **system** service failed with `HOME: unbound variable` (exit 1) at the cache-dir line. systemd system services start with no `$HOME`, and under `set -u` the `${XDG_CACHE_HOME:-$HOME/.cache}` fallback aborts. The script now defaults `$HOME` to the running user's home (`/root` for the system scan) when it is unset — complementing the `$SUDO_USER`/`$PKEXEC_UID` resolution, which only covers interactive sudo/pkexec. Regression from 2.9.1.

## 2.9.4 (2026-06-17) — personal fork
- Fix: `check_systemd` no longer flags a persistent `.timer` (`OnBootSec=` + `Persistent=true`) just for existing — it now vets the **service the timer triggers** and only warns when that target service is itself suspicious (ExecStart outside a standard prefix, not pacman-owned). This stops the scanner from flagging its own `/etc/systemd/system/archcanary.timer` (installed by `install.sh --system`) as a malicious persistence unit, which produced a false `RESULT: INFECTED` and desktop alert. A malicious timer pointing at `/tmp`, `$HOME`, etc. is still caught.

## 2.9.3 (2026-06-17) — personal fork
- New: the systemd units are now shipped under `systemd/` and `install.sh --system` installs and enables them — no more hand-creating files. It drops the root system scan units (`archcanary.{service,timer,path}` + `-onchange.service`) into `/etc/systemd/system/`, the user notifier (`archcanary-notify.{path,service}`) into `~/.config/systemd/user/`, pre-creates `/var/lib/archcanary/`, enables the timer + pacman trigger + notifier, and migrates away the old user-scope scan units. `uninstall --system` reverses all of it.
- Fix: the user notifier `.path` unit failed to start when `/var/lib/archcanary/` did not exist yet (inotify watch on a missing directory). The install now pre-creates the directory.

## 2.9.2 (2026-06-17) — personal fork
- Fix: a scan that skips root-requiring checks no longer reports a misleading `RESULT: CLEAN`. When `--check-kmod` / `--check-ebpf` / `--check-bpftool` (or `--full`) is run without root, those checks now return a dedicated "skipped" code; the run is reported as `INCOMPLETE: N root check(s) skipped` and the result escalates from CLEAN (0) to WARNINGS (exit 1) so automation and the systemd user service can detect that the scan was not complete. Run with `sudo` for the full picture. Genuine findings (exit 2) are unchanged.
- Change: systemd model reworked so automated scans get the **full picture**. The scan now runs as a **root system** service+timer (writes `/var/lib/archcanary/last-scan.log`), and a **user** `.path` unit watches that file and fires the desktop notification on a detection — replacing the old user-only service that silently skipped the root checks. `docs/systemd.md` rewritten with the new units and a migration note.
- Change: `install.sh --system` now also seeds the bundled package lists (`package_list.txt`, `malicious_npm_packages.txt`, `chaos_rat_packages.txt`) into `/usr/lib/archcanary/` so the root system scan finds them (root's `$HOME` is `/root`, which is not seeded).

## 2.9.1 (2026-06-17) — personal fork
- Fix: `sudo archcanary.sh --check-kmod` (and other root checks run directly with `sudo`) no longer fails with `Malicious npm package list not found: /root/.config/...`. When running as root via `sudo`, the script now resolves the invoking user's home from `$SUDO_USER` (and `$PKEXEC_UID` for the pkexec path) so package lists, the DKMS allowlist, and the log/cache dirs come from the user's `~/.config` / `~/.cache` instead of `/root`. Mirrors what the polkit root helper already did for the GUI.

## 2.9.0 (2026-06-17) — personal fork
- Removed: `archcanary-menu.sh` (fzf TUI) — the yad GUI covers interactive desktop use and the CLI (`archcanary.sh --full` / single `--check-*` flags) covers headless / SSH. The menu had drifted (missing yarn/pnpm checks) and its "View last log" used the abandoned journalctl path. Two surfaces now: GUI + CLI.
- Removed: `notify-send.sh` dependency and the notification action button. The exit-code-2 alert now uses plain `notify-send` (libnotify) with no button; open Archcanary from the app launcher to review and remediate.
- Removed: "View last log" from the GUI — the per-session status column already shows pass/fail per check; re-run a check to see its detail.
- Removed: orphaned `IS_FULL_SCAN` header marker (only ever fed the now-deleted GUI log picker).
- Fix: `install.sh` used `local` outside a function in the uninstall path (runtime error on `bash`).
- Dependencies dropped: `fzf`, `notify-send.sh`.

## 2.8.5 (2026-06-16) — personal fork
- New: `DKMS_ALLOWLIST` env var (colon-separated module names) — DKMS modules installed outside pacman by proprietary hardware drivers (e.g. `tuxedo-drivers`) can be acknowledged without suppressing genuine unknown-module warnings. Allowlisted entries print INFO instead of WARNING and do not set exit 2.

## 2.8.4 (2026-06-16) — personal fork
- Fix: `check_kmod` module name matching — `lsmod` returns names with underscores (`snd_seq_dummy`) but pacman `.ko` filenames use hyphens (`snd-seq-dummy.ko.zst`); normalize both to underscores before comparison, eliminating 80+ false positives from standard kernel modules
- Fix: `check_autostart` when run as root (`sudo`) now uses the invoking user's home dir (`$SUDO_USER`) instead of `/root` — `/root/.config/autostart/` holds live-session relics whose bare command names are unresolvable in root's PATH
- Docs: eBPF `lsm` warning now mentions AppArmor/SELinux as a legitimate source (Manjaro enables AppArmor by default)

## 2.8.3 (2026-06-16) — personal fork
- Fix: `check_systemd` now also skips services whose `ExecStart=` binary lives under a standard system prefix (`/usr/`, `/opt/`, `/bin/`, `/sbin/`, `/usr/local/`) and actually exists on disk — handles proprietary installers (piavpn, forgejo) that write a `.service` file without registering it with pacman. Malware still gets caught because it points to binaries in `/tmp/`, `$HOME/`, `/dev/shm/`, etc.

## 2.8.2 (2026-06-16) — personal fork
- Fix: run logs now default to `~/.cache/archcanary/` (`$XDG_CACHE_HOME`) instead of the current working directory — prevents log accumulation in the repo or install source dir

## 2.8.1 (2026-06-16) — personal fork
- Fix: `check_systemd` no longer flags pacman-owned `.service` / drop-in `.conf` files — legitimate system daemons from packages carry `Restart=on-failure` by design. Timer check is now skipped for user-space dirs (`~/.config/systemd/user/`) since `OnBootSec + Persistent=true` is standard for user timers (cron replacements, update schedulers).
- Fix: `check_autostart` desktop check now uses `command -v` to resolve bare names before flagging, and accepts all standard system prefixes (`/bin/`, `/sbin/`, `/usr/local/`) in addition to `/usr/` and `/opt/`.
- Fix: `check_autostart` user service check expands systemd `%h` to `$HOME` before querying `pacman -Qo`; skips `~/.local/bin/` and `~/bin/` (XDG user bin dirs, not tracked by pacman).
- Fix: `check_autostart` shell RC eval pattern now requires the subshell to open with a network/execution tool (`curl`, `wget`, `python`, `bash`, `sh`) — bare `eval $(dircolors ...)` and similar are no longer flagged.

## 2.8.0 (2026-06-16) — personal fork
- New: `--check-kmod` (included in `--full`) — audits loaded kernel modules against the full set of `.ko` files owned by pacman packages; flags any module with no traceable owner. Also checks `dkms status` for DKMS modules whose source package is not in `pacman -Q`. Requires root for reliable module attribution; skips gracefully otherwise. `LSMOD_CMD` / `DKMS_CMD` env vars injectable for testing.

## 2.7.1 (2026-06-16) — personal fork
- Improved: `--check-pkgbuild` now detects four additional obfuscation patterns beyond the original quote-stripping: base64-decode-to-shell (`base64 -d | bash`), `eval`+subshell (`eval $(...)`, eval+backtick), `printf` hex/octal escape sequences, and variable-split command reassembly (`a=bu; b=n; $a$b add`)
- `PKGBUILD_CACHE_DIRS` env var (colon-separated) overrides AUR helper cache locations for testing

## 2.7.0 (2026-06-16) — personal fork
- New: `--check-autostart` (included in `--full`) — detects low-privilege persistence requiring no root: suspicious XDG autostart `.desktop` files (`Exec=` outside `/usr/` or `/opt/`), user systemd services whose `ExecStart=` binary is untracked by pacman, and shell RC files (`.bashrc`, `.zshrc`, `.bash_profile`, `.profile`) containing download-and-execute or `eval`+subshell patterns
- Home dir injectable via `AUTOSTART_HOME` for testing

## 2.6.1 (2026-06-16) — personal fork
- Fix: `check_systemd` no longer requires the exact `Restart=always` + `RestartSec=30` pair from the 2024 campaign — now flags any of `always|on-failure|on-abnormal|on-abort` in `.service` files
- New: also scans drop-in override dirs (`*.service.d/*.conf`) — attackers use these to re-enable restart on existing units without modifying the unit file itself
- New: detects `.timer` units with `OnBootSec=` + `Persistent=true` — a common alternative to `.service` persistence that the original check missed entirely
- Scan dirs injectable via `SYSTEMD_SCAN_DIRS` (colon-separated) for testing

## 2.6.0 (2026-06-16) — personal fork
- New: `--check-ldso` (included in `--full`) — detects shared library injection via `/etc/ld.so.preload`; any non-empty content causes the dynamic linker to load the listed `.so` into every process at startup. Hard indicator of root-level compromise; lists each injected library verbatim (exit 2).

## 2.5.1 (2026-06-16) — personal fork
- Fix: Check [2] historical log now shows full ISO timestamp (`2026-06-10T14:23:45+0100`) instead of date-only, so the exact install time is visible alongside the package name
- Improved: Check [2] WARNING output now explains these are name-matches and that a clean-looking PKGBUILD may mean the malicious commit was reverted — clarifies context without dismissing the risk

## 2.5.0 (2026-06-16) — personal fork
- New: `--check-bpftool` (included in `--full`) — enumerates **all** loaded eBPF programs via `bpftool prog show`, complementing `--check-ebpf` (which only globs pinned `/sys/fs/bpf/hidden_*` maps). Catches unpinned or differently-named programs an eBPF rootkit may keep alive via an open fd or a BPF link. Informational by default; **warns** (exit 1) when stealth-associated hook types are present (`kprobe`/`kretprobe`/`tracepoint`/`raw_tracepoint`/`perf_event`/`tracing`/`lsm`). Requires root to enumerate; skips gracefully otherwise. Needs the `bpf` package (provides `bpftool`).
- Change: `install.sh` now prefers `~/.local/bin` (XDG) over `~/bin`

## 2.4.0 (2026-06-14) — personal fork
- New: XDG config dir — package lists live in `~/.config/archcanary/` (respects `$XDG_CONFIG_HOME`); created automatically on first run
- New: auto-seed config dir from bundled txt files when running from a new install location
- New: `--check-pkgbuild` (included in `--full`) — obfuscation-aware scan of AUR helper caches (`~/.cache/yay`, `~/.cache/paru`, etc.) for `bun add` / `npm install` of malicious packages; catches quote-split commands like `'b''u''n' 'a'"d""d"`
- New: `nextfile-js` added to malicious npm package list (reported upstream issue #11 / PR #12)
- New: `archcanary-menu.sh` — fzf TUI menu to run individual checks or view the last log; loops back to menu after each action
- New: `--no-notify` flag — suppresses desktop notification when called as subprocess (e.g. from the menu)
- Improved: notification prefers `notify-send.sh` (AUR) over plain `notify-send`; adds a **Show Menu** button that opens `archcanary-menu.sh` in a terminal when clicked
- Package list refreshed to 1936 entries

## 2.3.3 (2026-06-13)
- Fix: prefix-matching bug in `check_current()` (Issue #2, confirmed via opencode/opencode-bin)
- New: `INFECTED_LOOKUP` associative array filters `pacman -Qmq` results to exact matches only
- `[[ -v INFECTED_LOOKUP["$pkg"] ]] || continue` prevents false positives on -bin/-git suffixed packages

## 2.3.2 (2026-06-13)
- New: `--all-time` flag (v2) — disable recency window for cross-campaign detection
- New: `custom_list_merge_aur_scan.sh` — fetch HedgeDoc + merge custom lists +
  dedup + run archcanary.sh
  - `-l/--list=URL|FILE`: additional AUR package lists (repeatable)
  - `-m/--malicious-npm=URL|FILE`: additional npm lists (repeatable)
  - `--skip-hedgedoc`: exclude official HedgeDoc list
  - `-o/--output=FILE`: save merged list
  - `-v/--verbose`, `--debug`: verbosity control (+ set -x trace for debug)
  - `--list=`, `--malicious-npm=` value-consumption via `((++i))` (fix: `set -e`
    kill at `((0++))` on first iteration)
  - `info()`: `if $VERBOSE; then` instead of `$VERBOSE &&` (fix: non-zero return
    with `set -e` when not verbose)
  - `$PASSTHROUGH &&` → `[[ "$PASSTHROUGH" == true ]] &&` (fix: bare `false &&`
    fragile)
  - `append_source` loops: `&& counter++` instead of `; counter++` (fix: counts
    only successful sources)
  - Warning banner when `-l`/`-m` used: name-based match ≠ IOC verification
  - `--all-time` removed from hardcoded exec — user passes via `-- --all-time`
  - Edge cases: --skip-hedgedoc without -l → error; fetch timeout → skip

## 2.3.1 (2026-06-13)
- New: `--package-list=PATH` CLI flag — override infected AUR package list path
- New: `--malicious-npm-list=PATH` CLI flag — override malicious npm package list path
- Change: CLI flags override env vars override defaults (`PACKAGE_LIST_FILE`, `MALICIOUS_NPM_LIST`)
- Change: warn if `--package-list` and `--refresh` conflict, ignore `--refresh`
- New: `tests/run_matching_tests.sh` — 8-test matching test suite
  - suffix_ambiguity: `jd-gui` vs `jd-gui-bin` exact matching (regression guard for #2)
  - substring: short names don't match suffixed variants
  - empty list, comments, specials, CLI flag integration

## 2.3.0 (2026-06-13)
- New: `--refresh` flag — fetch live package list from Arch Linux HedgeDoc (1619 packages)
- New: `lockfile-js` added to npm+bun cache checks (3rd malicious npm package)
- PR #8 (drbbgh): package list refresh logic with `/download` endpoint
- PR #7 (liphiwolf): lockfile-js detection, package list expanded from CSCS paste
- Campaign banner updated: atomic-lockfile / js-digest / lockfile-js
- Package list: ~588 → 1619 (live via `--refresh`) / 512 (bundled fallback)

## 2.2.0 (2026-06-12)
- Correction: `arojas` was impersonated via git commit forgery, not a malicious maintainer
- `iocs.txt`: `arojas` moved to new "Impersonated Accounts" section
- New sources: mttaggart Mastodon thread, David Runge clarification
- Banner + attack vector text corrected in README

## 2.1.0 (2026-06-12)
- New attack wave: bun/js-digest variant (second malicious npm package)
- 29 new compromised packages (custodiatovar + veramagalhaes accounts)
- `--check-bun-cache`: scan bun cache for js-digest / atomic-lockfile
- `check_npm_cache` expanded: detects atomic-lockfile AND js-digest
- New IOC: js-digest ELF SHA256 7883BD...
- New attacker accounts custodiatovar, veramagalhaes in iocs.txt

## 2.0.0 (2026-06-12)
- `archcanary.sh`: optimized log scanner (bash regex + O(1) assoc. array)
- Same detection logic as v1, ~150x faster for large pacman.log files
- v1 retained for completeness as reference implementation

## 1.1.0 (2026-06-12)
- Fix: `set -e` bug — non-verbose mode killed script (log_info always returns 0)
- Auto-logfile: full detail always written to `aur-check-<date>.log`
- Terminal output gated by `--verbose`; log always contains `[INFO]` detail
- `check_logs` output now visible on terminal via `tee` (was hidden in tempfile)
- Informative eBPF message on missing privileges
- `exit "$EXIT_CODE"` quoting, mktemp everywhere, trap for tempfile cleanup
- Pipe-to-subshell fixed: `while read` now uses process substitution

## 1.0.0 (2026-06-12)
- Consolidated archcanary.sh combining all 5 community forks
- Package list: ~588 known compromised AUR packages
- Detection: current install + pacman logs + date window
- Optional checks: systemd, eBPF, npm cache
- IOC reference document
- Full source attribution in README

### Integration History
- Base list: Kidev original (446 packages)
- Extended: commonsourcecs fork (+~140 packages)
- Efficiency: BrianCArnold, commonsourcecs batch query
- Log scanning: Kacper-Kondracki pacman.log parser
- Safety: quantenProjects comm approach
