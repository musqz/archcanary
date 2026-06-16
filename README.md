# AUR Malware Check - June 2026 Campaign

Detection and analysis tools for the **atomic-lockfile** supply-chain attack on the Arch User Repository (AUR).

This is a collection of all the scattered resources, especially the ones in the detection scripts Gist - they made this, I just collected this to a repo so I have it all in one place and possibly people could put up PR's instead of Gist links across multiple posts. Certainly see the source section for details on the sources!

> [!TIP]
> **Questions, support, or general discussion?** Head over to
> [Discussions](https://github.com/lenucksi/aur-malware-check/discussions/).
> Issues are reserved for bug reports and feature requests only.

> [!TIP]
> **Python 3.14+ version available?** See `aur_check_py/` — stdlib-only, typed,
> testable, should be functionally identical, please test and report back.

> **1600+ AUR packages compromised** by attackers who injected `npm install atomic-lockfile`, `bun install js-digest`, or `lockfile-js` into PKGBUILD/install files. Two attack waves:
> 1. **atomic-lockfile / lockfile-js** (npm) — accounts `krisztinavarga`, `franziskaweber`, `tobiaswesterburg`, `ellenmyklebust`; `arojas` (impersonated legitimate maintainer — see Impersonation Clarification)
> 2. **js-digest** (bun) — accounts `custodiatovar`, `veramagalhaes`
>
> Both deliver an **infostealer** and **eBPF rootkit** targeting developer credentials, browser data, and CI/CD secrets.

## Quick Start

```bash
# Check if you have any infected packages
./aur_check-v2.sh

# Check bun cache specifically (for js-digest / atomic-lockfile)
./aur_check-v2.sh --check-bun-cache

# Safe one-liner (from quantenProjects) - just compare installed vs infected list
comm -1 -2 <(pacman -Qq | sort) <(curl -s https://raw.githubusercontent.com/lenucksi/aur-malware-check/master/package_list.txt | sort)

# Full scan with all optional checks
./aur_check-v2.sh --full

# Cross-campaign: scan all installed packages regardless of install date
./aur_check-v2.sh --all-time

# Merge multiple lists (HedgeDoc + historical + custom) and scan
./custom_list_merge_aur_scan.sh -l ./historical_packages.txt

# Merge custom lists and disable date window for cross-campaign scan
./custom_list_merge_aur_scan.sh -l ./historical_packages.txt -- --all-time

# Refresh the package list from the official Arch Linux HedgeDoc, then scan
./aur_check-v2.sh --refresh --full

# Use custom package lists (also settable via env vars):
#   PACKAGE_LIST_FILE=./my_list.txt
#   MALICIOUS_NPM_LIST=./my_npm.txt
./aur_check-v2.sh --package-list=my_list.txt --malicious-npm-list=my_npm.txt


# Legacy scan (only use if v2 is broken)
./archive/aur_check.sh
```

## Script: `aur_check.sh`

A consolidated detection script combining the best features from all community forks:

| Feature | Source |
|---------|--------|
| Batch `pacman -Qmq` query | commonsourcecs fork |
| Date window filtering (Jun 9-12) | commonsourcecs fork |
| Historical pacman.log scanning | Kacper-Kondracki fork |
| Compressed log support (.gz/.xz/.zst/.bz2) | Kacper-Kondracki fork |
| ~1600 known compromised packages (live via `--refresh`) | Consolidated from all sources + HedgeDoc |
| systemd persistence check | Original addition |
| eBPF rootkit check | Original addition |
| npm cache check (atomic-lockfile / js-digest / lockfile-js) | Original addition |
| bun cache check (atomic-lockfile / js-digest / lockfile-js) | Original addition |
| `--refresh` flag (live package list) | PR #8 (drbbgh) |
| `--package-list=PATH` CLI flag | Original addition |
| `--malicious-npm-list=PATH` CLI flag | Original addition |
| Configurable date window via env vars | Kacper-Kondracki fork |

### Script Versions

Two versions are maintained — v2 is optimized but functionally identical:

| Version | File | Log Scanning | Speed (6.2 MB pacman.log) |
|---------|------|-------------|--------------------------|
| v1 | `aur_check.sh` | `echo \| sed` subprocesses + `grep -xF` tempfile | ~3-5 min |
| v2 | `aur_check-v2.sh` | Bash regex (`[[ $line =~ $re ]]`) + O(1) assoc. array | ~1-2 s |

v2 verified against v1 by static analysis: **8/10 risk categories NONE, 2/10 LOW** (theoretical edge cases only, no real inputs affected). Use v2 for speed; v1 retained as reference for completeness.

### Exit Codes

- **0**: Clean - no indicators found
- **1**: Warnings (log scan issues, missing files)
- **2**: Infected packages or artifacts detected

## Repository Structure

```
aur-malware-check/
├── README.md              # This file
├── aur_check.sh           # v1: Consolidated detection script (sed+grep log scanner)
├── aur_check-v2.sh        # v2: Optimized log scanner (bash regex + O(1) hash lookup)
├── package_list.txt              # bundled compromised packages, same as --refresh one as of 6/17/26. (1619 via `--refresh`)
├── malicious_npm_packages.txt    # Malicious npm package names for cache checks
├── iocs.txt                      # Indicators of Compromise
├── CHANGELOG.md           # Version history
├── sources/               # Original community scripts
│   ├── 01_kidev_original.sh
│   ├── 02_briancarnold_fork.sh
│   ├── 03_kacper-kondracki_fork.sh
│   └── 04_quantenprojects_list.txt
├── fetches/               # Raw fetched content (for verification)
├── SOURCES.md             # Numbered, sectioned source references
├── at_risk_accounts.json  # All identified attacker/monitoring accounts with status
├── tests/
│   ├── run_matching_tests.sh           # Matching test runner
│   ├── fake_package_lists/             # Fake infected AUR package lists for tests
│   └── fake_npm_lists/                 # Fake malicious npm package name lists for tests
└── subagent-reports/      # Extracted subagent analysis reports
```

## Sources

This analysis aggregates information from the following sources:

### Primary Reports

| Source | URL | Content Used |
|--------|-----|-------------|
| IFIN Discourse | https://discourse.ifin.network/t/400-aur-packages-compromised-with-infostealer-and-rootkit/577 | Attack summary, links, **bun/js-digest wave update (Jun 12)** |
| ioctl.fail Analysis | https://ioctl.fail/preliminary-analysis-of-aur-malware/ | Detailed technical analysis, IOCs, eBPF rootkit details, C2 extraction |
| Arch ML: Main Thread | https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/FGXPCB3ZVCJIV7FX323SBAX2JHYB7ZS4/ | Master list of ~408 packages by Andre Herbst, additional reports by Rafal Lichwala, Nicolas Boichat, Damien |
| Arch ML: HedgeDoc Package List | https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/message/FCH7TT6IOVT7D477JKSVJALBKADAARSW/ | Jonathan Grotelüschen (Arch Staff) posts HedgeDoc link with updated affected package list |
| Arch ML: ALVR Report | https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/2LGBF2AZBPVCCY4VTN6DOVUNNBURFJ2J/ | First report of suspicious commit on alvr package |
| ALVR AUR Page | https://aur.archlinux.org/packages/alvr | User comments detailing compromise analysis |

### Community Detection Scripts

| Source | URL | Contribution |
|--------|-----|-------------|
| **Kidev (Original)** | https://gist.github.com/Kidev/59bf9f5fb53ab5eee99f19a6a2fc3992 | Foundation: initial package list (~446), basic `pacman -Qi` check loop |
| **BrianCArnold (Fork)** | https://gist.github.com/BrianCArnold/beb514ffc95a9a251b0dc2f767471fca | Efficiency improvement: `pacman -Qm` piped through grep |
| **commonsourcecs (Fork)** | https://cscs.pastes.sh/aurvulntest20260611.sh | Batch `pacman -Qmq` query, install date window (Jun 9-12), expanded package list (~1620) |
| **Kacper-Kondracki (Fork)** | https://gist.github.com/Kacper-Kondracki/88c5b313f79cc1f9c347e7ed61a36d10 | Historical pacman.log scanning with compressed file support, configurable date window via env vars |
| **quantenProjects (Fork)** | https://gist.github.com/quantenProjects/3f768dce7331618310f016d975bf8547 | Safe non-executable package list, `comm -1 -2` one-liner approach |

### bun/js-digest Wave Reports (June 12)

| Source | URL | Content Used |
|--------|-----|-------------|
| **Cedric Girard** (aur-general) | https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/LB6TBHDXLQRPR4UVIQULCI6MZ77XYLL2/ | First report of bun/js-digest wave (guiscrcpy, netmon-git) |
| **ValdikSS** (aur-general) | https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/LB6TBHDXLQRPR4UVIQULCI6MZ77XYLL2/ | Identification of custodiatovar account (13 malicious packages) |
| **Marcin Wieczorek / Thorsten Wißmann** (aur-general) | https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/LB6TBHDXLQRPR4UVIQULCI6MZ77XYLL2/ | Report of inadyn-mt, veramagalhaes account (13 packages), commit forgery proof for nodejs-elm |
| **IFIN Discourse (Update)** | https://discourse.ifin.network/t/400-aur-packages-compromised-with-infostealer-and-rootkit/577 | js-digest SHA256, bun variant documentation, keepassx2 example |
| **Socket.dev** | https://socket.dev/npm/package/js-digest | js-digest metadata, pulled from NPM confirmation |

### Mailing List — Attack Reports & Account Identification

| Source | URL | Content Used |
|--------|-----|-------------|
| **Fabio Loli** | https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/message/LVYB62N3FPAWUHNJ5Z5GXG6OIR7S5P3F/ | Reports **franziskaweber**, **tobiaswesterburg**, **ellenmyklebust** as malicious (npm shenanigans) |
| **Sasha Moak** | https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/message/CIKQJQI3AREXIR6IQVWPBYFJPYLM45EF/ | Additional suspicious packages (android-support-repository, monochrome, blinkenlib, perl-set-object) |
| **Joom** | https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/message/NCLGU23LSLOFXMBGG7HH67EWDZC2TJB3/ | **ivonahruskova** — account created Jun 11, 16 adoptions, under monitoring |
| **Paul** | https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/message/K2ZO3U4WPV7BBT2WAP5P54F23A37RUPH/ | **simongeisler** — 3-day-old account, 16 orphan adoptions, under monitoring |

### Mailing List — Proposals & Community Discussion

| Source | URL | Content Used |
|--------|-----|-------------|
| Proposal: Commit Hashes | https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/WJ5CH64QMWSFGIJYFSRVEFLSNI7JSKPR/ | Compile per-package affected commit hashes + date ranges |
| Proposal: AUR Read Only | https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/WS2K2XGMLPBFZ3WGOPLF2UP32HZJ6ZSP/ | 16-participant discussion about making AUR read-only |
| Idea: Prevent Malicious Pkgs | https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/7QZREKFQX3P3UOQNUYJOXANPK4PFH733/ | Long-term mitigation ideas |
| AURSCAN (LLM Scanner) | https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/E26JEFVSR6YG4GBQUZYDMWYCXD7S7N5V/ | Andreas Reichel: YAY wrapper scanning PKGBUILD with Claude LLM. Local alternatives discussed (Qwen2.5-Coder-7B, Haiku POC) |

### Impersonation Clarification

| Source | URL | Content Used |
|--------|-----|-------------|
| **mttaggart** (IFIN) | https://infosec.exchange/@mttaggart/116735530761603752 | Initial report raising arojas question; later corrected to note impersonation after dvzrv clarification |
| **David Runge** (Arch Linux TU) | https://chaos.social/@dvzrv/116736017948300691 | Confirms arojas is legitimate KDE maintainer, attacker reused his identity via git commit forgery; requests corrections |
| **IFIN Discourse (Updated)** | https://discourse.ifin.network/t/400-aur-packages-compromised-with-infostealer-and-rootkit/577 | Post corrected — now explicitly notes arojas was impersonated |

### Community Contributions

| Source | URL | Content Used |
|--------|-----|-------------|
| **drbbgh** (PR #8) | https://github.com/lenucksi/aur-malware-check/pull/8 | `--refresh` flag: live package list fetch from Arch Linux HedgeDoc |
| **liphiwolf** (PR #7) | https://github.com/lenucksi/aur-malware-check/pull/7 | `lockfile-js` detection, expanded package list from CSCS paste |
| **0xf836** (PR #4) | https://github.com/lenucksi/aur-malware-check/pull/4 | Package list expansion (superseded by PR #8) |

### Additional Data

| Source | URL | Content Used |
|--------|-----|-------------|
| IRC Package List | https://gr.ht/aur_pkg_list.txt | Additional compromised packages from IRC |
| Malicious npm Package | https://socket.dev/npm/package/atomic-lockfile | Package metadata, download count (134) |
| Attacker GitHub Container | https://github.com/fardewoak/nodejs-argo/pkgs/container/herbsobering430 | Reverse shell/proxy tool tied to attacker |
| AUR Example Commit | https://aur.archlinux.org/cgit/aur.git/commit/?h=premake-git&id=232b22dd0aaedfa9fde1800710e0d52e4f4b542d | Example of malicious commit |

## Incident Overview

### Timeline

- **June 9-12, 2026**: Malicious commits pushed to 408+ AUR packages
- **June 11**: First report on aur-general mailing list (Kusoneko about alvr)
- **June 11**: Andre Herbst discovers scope by grepping AUR git mirror
- **June 11**: ioctl.fail publishes technical analysis
- **June 12**: Community detection scripts published; AUR maintainers cleaning up
- **June 12**: David Runge clarifies `arojas` was impersonated via git commit forgery, not a malicious maintainer
- **June 12, 17:33**: Jonathan Grotelüschen posts HedgeDoc with updated affected package list
- **June 13**: New monitoring accounts identified (ivonahruskova, simongeisler); proposals for commit hash tracking, AUR read-only, and LLM-based scanning discussed
- **June 13**: PR #8 (drbbgh) merged — `--refresh` flag for live HedgeDoc package list
- **June 13**: PR #7 (liphiwolf) merged — `lockfile-js` detection, expanded package list

### Attack Vector — Wave 1: atomic-lockfile / lockfile-js (npm)

1. Attacker used commit forgery to impersonate maintainer `arojas` (see Impersonation Clarification below)
2. Took over orphaned AUR packages via the forged identity
3. Injected `npm install atomic-lockfile` or `npm install lockfile-js` into `.install` and `.hook` files
4. The npm packages `atomic-lockfile@1.4.2` / `lockfile-js` contained a `preinstall` hook executing `./src/hooks/deps`
5. The ELF binary `deps` (SHA256: `6144D4...`) is a Rust-based credential stealer

### Attack Vector — Wave 2: js-digest (bun)

1. Additional attacker accounts `custodiatovar` and `veramagalhaes` took over orphaned packages
2. Injected `bun install js-digest` into PKGBUILD/`.install` files (same NPM publisher `herbsobering`)
3. The npm package `js-digest` contained an embedded ELF payload (SHA256: `7883BD...`)
4. Affected packages include guiscrcpy, netmon-git, inadyn-mt, nodejs-elm, keepassx2, and 26+ more

### Malware Capabilities

- **Credential theft**: Discord tokens, GitHub PATs, npm tokens, Slack sessions, Teams/M365 sessions, SSH keys, Vault tokens, Docker/Podman credentials, browser cookies
- **Data exfiltration**: Uploads to `temp.sh`, C2 via Tor onion service
- **Persistence**: systemd services (root or user mode) with `Restart=always`
- **eBPF rootkit**: When run as root with CAP_BPF, hides processes, files, and socket inodes
- **Cryptominer staging**: References `/usr/bin/monero-wallet-gui` for potential crypto mining payload

## What to Do If Infected

1. **Preserve the system**: Do not power off - use forensic acquisition with trusted media
2. **Rotate ALL credentials**: Discord, GitHub, npm, Slack, Teams, SSH keys, Vault tokens, cloud provider keys
3. **Check for persistence**: `systemctl list-units --type=service --state=running` (check for unknown services)
4. **Check for eBPF rootkit**: `ls -la /sys/fs/bpf/hidden_*`
5. **Clean with trusted media**: Boot from Arch ISO, mount filesystem, remove malicious systemd units
6. **Consider reinstallation**: The rootkit makes the system untrustworthy
7. **Report findings**: https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/

## License

Community tools - no warranty. Use at your own risk.

## Star History

<a href="https://www.star-history.com/?repos=lenucksi%2Faur-malware-check&type=date&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=lenucksi/aur-malware-check&type=date&theme=dark&legend=top-left" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=lenucksi/aur-malware-check&type=date&legend=top-left" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=lenucksi/aur-malware-check&type=date&legend=top-left" />
 </picture>
</a>
