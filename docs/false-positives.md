# Known false positives — traur signals

Signals that fire reliably on benign packages due to structural reasons, not malicious behaviour.
Each entry records the signal, the affected package pattern, the exact file that triggers it, why it is safe, and when the decision was last verified.

> **Operational note:** do not suppress these signals globally. Let them fire, check this register, confirm the flagged file matches what is documented here, then proceed. If a signal fires on a file *not* listed in this register, treat it as real.

---

## P-SUID-BIT — Setting SUID/SGID bit

**Affected packages:** `electron*-bin`, `chromium`, `chromium-bin`, `brave-bin`, `vivaldi`, `vivaldi-stable`, `microsoft-edge-*-bin`, `google-chrome`, `google-chrome-beta`, `google-chrome-dev`

**Triggering file:** `chrome-sandbox` (e.g. `/usr/lib/electron40/chrome-sandbox`)

**Permissions:** `4755` (SUID root)

**Why it is a false positive:**
`chrome-sandbox` is the Chromium renderer sandbox helper. It requires SUID root to create an isolated user namespace (or fall back to setuid sandboxing) for each renderer process. This is an upstream security feature — it *reduces* privilege of renderer processes, it does not escalate them. The binary is part of the official Electron/Chromium release tarball and is not added by the AUR maintainer.

**How to confirm:** verify the flagged file is `chrome-sandbox` and is owned by root:

```bash
stat /usr/lib/electronNN/chrome-sandbox
# Expected: File: /usr/lib/electronNN/chrome-sandbox
#           Access: (4755/-rwsr-xr-x)  Uid: (0/root)
```

**Last verified:** 2026-06-17 (`electron40-bin`, `/usr/lib/electron40/chrome-sandbox`, mode `4755`)

---

## Adding new entries

When you encounter a signal that you have confirmed is a false positive:

1. Identify the exact file that triggered the signal (`stat`, `pacman -Ql <pkg>`).
2. Research why the file behaves that way upstream.
3. Add an entry here following the format above.
4. Commit with the date verified.

Do not add an entry based on trust alone — always confirm the specific file.
