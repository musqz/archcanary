# paru integration

Not part of [my-setup.md](my-setup.md) (that page documents a real yay-based
setup) — this covers the equivalent hook for anyone using paru instead.

paru's native `PreBuildCommand` hook (`~/.config/paru/paru.conf`, `[bin]` section) — seeded by `install.sh` **only when paru is installed and no `PreBuildCommand` is already configured** (source: [`configs/paru-hook.conf`](../configs/paru-hook.conf)). Unlike yay's `init.lua`, this edits a file paru itself may already use for other settings, so seeding is gated on paru actually being present, and `install.sh` never touches an existing `PreBuildCommand` line — if you already have one (ours or your own), re-copy `configs/paru-hook.conf`'s line by hand to pick up a newer version.

Runs `archcanary --check-pkgbuild` before every AUR build, scoped to just that package's own build directory (`PKGBUILD_CACHE_DIRS=.`) — a nonzero exit (pattern match found) genuinely aborts the build, since paru propagates `PreBuildCommand`'s exit status as a real error. `--no-notify --no-summary` keep this silent-unless-flagged on every single build. Fails open if archcanary isn't on `$PATH` (build proceeds rather than hard-blocking on a missing optional dependency).

**Limitation:** `PreBuildCommand` fires before paru's own diff/edit review menus (confirmed in paru's source, `src/install.rs`) — paru has no post-review hook point to move it to, unlike yay's `AURPostDownload`. It's also narrower in scope than yay's hook: only the PKGBUILD pattern check, no aur-audit black/red lookup, and no equivalent to yay's non-abort "press Enter to continue" checkpoint — a clean paru build stays fully silent (`--no-notify --no-summary`) and never pauses.

Uninstalling removes just the two hook lines (marker comment + `PreBuildCommand`) from `paru.conf` — the rest of the file, including the `[bin]` section header itself, is left untouched.
