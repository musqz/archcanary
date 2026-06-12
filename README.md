# AUR Malware Check - June 2026 Campaign

Detection and analysis tools for the **atomic-lockfile** supply-chain attack on the Arch User Repository (AUR).

This is a collection of all the scattered resources, especially the ones in the detection scripts Gist - they made this, I just collected this to a repo so I have it all in one place and possibly people could put up PR's instead of Gist links across multiple posts. Certainly see the source section for details on the sources!

> **408+ AUR packages compromised** by a malicious maintainer (`arojas`) who injected `npm install atomic-lockfile` into PKGBUILD/install files. The malicious npm package delivers an **infostealer** and **eBPF rootkit** targeting developer credentials, browser data, and CI/CD secrets.

## Quick Start

```bash
# Check if you have any infected packages
chmod +x aur_check.sh
./aur_check.sh

# Full scan with all optional checks
./aur_check.sh --full

# Safe one-liner (from quantenProjects) - just compare installed vs infected list
comm -1 -2 <(pacman -Qq | sort) <(curl -s https://raw.githubusercontent.com/YOUR/aur-malware-check/main/package_list.txt | sort)
```

## Script: `aur_check.sh`

A consolidated detection script combining the best features from all community forks:

| Feature | Source |
|---------|--------|
| Batch `pacman -Qmq` query | commonsourcecs fork |
| Date window filtering (Jun 9-12) | commonsourcecs fork |
| Historical pacman.log scanning | Kacper-Kondracki fork |
| Compressed log support (.gz/.xz/.zst/.bz2) | Kacper-Kondracki fork |
| ~588 known compromised packages | Consolidated from all sources |
| systemd persistence check | Original addition |
| eBPF rootkit check | Original addition |
| npm cache check | Original addition |
| Configurable date window via env vars | Kacper-Kondracki fork |

### Exit Codes

- **0**: Clean - no indicators found
- **1**: Warnings (log scan issues, missing files)
- **2**: Infected packages or artifacts detected

## Repository Structure

```
aur-malware-check/
├── README.md              # This file
├── aur_check.sh           # Consolidated detection script
├── package_list.txt       # All ~588 known compromised packages
├── iocs.txt               # Indicators of Compromise
├── CHANGELOG.md           # Version history
├── sources/               # Original community scripts
│   ├── 01_kidev_original.sh
│   ├── 02_briancarnold_fork.sh
│   ├── 03_kacper-kondracki_fork.sh
│   └── 04_quantenprojects_list.txt
├── fetches/               # Raw fetched content (for verification)
└── subagent-reports/      # Extracted subagent analysis reports
```

## Sources

This analysis aggregates information from the following sources:

### Primary Reports

| Source | URL | Content Used |
|--------|-----|-------------|
| IFIN Discourse | https://discourse.ifin.network/t/400-aur-packages-compromised-with-infostealer-and-rootkit/577 | Attack summary, links to other resources |
| ioctl.fail Analysis | https://ioctl.fail/preliminary-analysis-of-aur-malware/ | Detailed technical analysis, IOCs, eBPF rootkit details, C2 extraction |
| Arch ML: Main Thread | https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/FGXPCB3ZVCJIV7FX323SBAX2JHYB7ZS4/ | Master list of ~408 packages by Andre Herbst, additional reports by Rafal Lichwala, Nicolas Boichat, Damien |
| Arch ML: ALVR Report | https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/2LGBF2AZBPVCCY4VTN6DOVUNNBURFJ2J/ | First report of suspicious commit on alvr package |
| ALVR AUR Page | https://aur.archlinux.org/packages/alvr | User comments detailing compromise analysis |

### Community Detection Scripts

| Source | URL | Contribution |
|--------|-----|-------------|
| **Kidev (Original)** | https://gist.github.com/Kidev/59bf9f5fb53ab5eee99f19a6a2fc3992 | Foundation: initial package list (~446), basic `pacman -Qi` check loop |
| **BrianCArnold (Fork)** | https://gist.github.com/BrianCArnold/beb514ffc95a9a251b0dc2f767471fca | Efficiency improvement: `pacman -Qm` piped through grep |
| **commonsourcecs (Fork)** | https://cscs.pastes.sh/aurvulntest20260611.sh | Batch `pacman -Qmq` query, install date window (Jun 9-12), expanded package list (~588) |
| **Kacper-Kondracki (Fork)** | https://gist.github.com/Kacper-Kondracki/88c5b313f79cc1f9c347e7ed61a36d10 | Historical pacman.log scanning with compressed file support, configurable date window via env vars |
| **quantenProjects (Fork)** | https://gist.github.com/quantenProjects/3f768dce7331618310f016d975bf8547 | Safe non-executable package list, `comm -1 -2` one-liner approach |

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

### Attack Vector

1. Attacker account `arojas` took over orphaned AUR packages
2. Used commit forgery (impersonated previous maintainer name/email)
3. Injected `npm install atomic-lockfile` into `.install` and `.hook` files
4. The npm package `atomic-lockfile@1.4.2` contained a `preinstall` hook executing `./src/hooks/deps`
5. The ELF binary `deps` (SHA256: `6144D4...`) is a Rust-based credential stealer

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
