# Contributing

## Reporting a malicious/suspicious AUR package

This is the most common and most useful contribution: archcanary maintains a
community-sourced list of individually-reported packages
(`lists/community_reports.txt`) that don't (yet) belong to a documented
campaign like CHAOS RAT or the Russian Spam Campaign. A merged report ships
to every archcanary user automatically on their next `--refresh`, annotated
`[community report]` in the scan output.

**Two ways to report, pick whichever is easier for you:**

### 1. Open an issue (no git knowledge needed)

Use the [Report a package](https://github.com/musqz/archcanary/issues/new?template=report-package.yml)
form. Fill in the package name and a link to whatever makes you believe
it's malicious or suspicious. That's it — someone will verify it and add it
to the list if it checks out.

### 2. Open a pull request directly

If you're comfortable with git, add the package name as a new line at the
end of `lists/community_reports.txt` and open a PR. Please use the PR
template — it asks for the same evidence link as the issue form, so the
PR can be reviewed without back-and-forth.

### What counts as evidence

A package name on its own can't be verified or acted on. Link to *something*
concrete:

- An AUR comment describing the malicious behavior
- A mailing-list post (e.g. `aur-general@lists.archlinux.org`)
- A PKGBUILD diff or analysis showing the obfuscated/malicious part
- A writeup, blog post, or forum thread

### Before submitting

Check the package isn't already covered — a duplicate report just adds
review overhead for no benefit:

```bash
grep -rF 'package-name-here' lists/
```

(This is the same check `archcanary --check-list-overlap` runs for your own
custom lists — see the README's "Checks" table.)

### What happens after that

Reports are reviewed by hand, not auto-merged — expect this to take a
while, not real-time. This is intentionally the slower, human-vetted path:
see the [aur-audit.wtako.net feed](README.md#aur-auditwtakonet-feed) if you
want a continuously-updated, best-effort automated signal instead — they're
complementary, not alternatives.

---

## Other contributions

Bug reports, feature ideas, and code PRs are welcome too — open an
[issue](https://github.com/musqz/archcanary/issues) or
[discussion](https://github.com/musqz/archcanary/discussions) first for
anything non-trivial, so we can agree on the approach before you put work
into it.
For code changes: run `bash tests/run_matching_tests.sh` before opening a
PR, and update `--help`/the man page/README if you changed user-facing
behavior.

archcanary is read-only by design — it detects and reports, it never
remediates. Keep that in mind if you're proposing a new check or flag.
