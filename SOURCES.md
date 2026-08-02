# Sources — Archcanary (June 2026)

Numbered and structured references for the atomic-lockfile / js-digest supply-chain attack on the Arch User Repository.

---

## 1. Primary Announcements

### 1.1 Arch Linux News — Incident Announcement
- **URL:** https://archlinux.org/news/active-aur-malicious-packages-incident/
- **Date:** 2026-06-12
- **Content:** Official Arch Linux announcement. AUR made read-only. Confirms 400+ compromised packages, two attack waves (atomic-lockfile / js-digest). Advises users to run detection scripts.
- **Relevant for:** Timeline, official response, AUR read-only measure.

### 1.2 HedgeDoc Package List (Jonathan Grotelüschen)
- **URL (HedgeDoc):** https://md.archlinux.org/s/SxbqukK6IA
- **URL (ML Post):** https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/message/FCH7TT6IOVT7D477JKSVJALBKADAARSW/
- **Date:** 2026-06-12, 17:33 UTC
- **Author:** Jonathan Grotelüschen (tippfehlr) — Arch Linux Staff / AUR Maintainer
- **Content:** Crowd-sourced list of affected packages. Updates from Andre Herbst's original ~408 list. ~50k views within hours.
- **Relevant for:** Package list, authoritative source.

---

## 2. Technical Analysis

### 2.1 ioctl.fail — Preliminary Analysis
- **URL:** https://ioctl.fail/preliminary-analysis-of-aur-malware/
- **Date:** 2026-06-11
- **Content:** Detailed technical analysis. IOCs, eBPF rootkit details (CAP_BPF, hides processes/files/socket inodes), C2 extraction via Tor onion service, systemd persistence, credential theft targeting Discord/GitHub/npm/Slack/SSH/Vault.
- **Relevant for:** Malware capabilities, IoCs, persistence mechanisms.

### 2.2 Socket.dev — atomic-lockfile (npm)
- **URL:** https://socket.dev/npm/package/atomic-lockfile
- **Date:** 2026-06-11
- **Content:** npm package metadata. SHA256 of embedded ELF payload (6144D4...). Preinstall hook analysis. 134 downloads.
- **Relevant for:** Wave 1 package verification.

### 2.3 Socket.dev — js-digest (npm)
- **URL:** https://socket.dev/npm/package/js-digest
- **Date:** 2026-06-12
- **Content:** npm package metadata. SHA256 of embedded ELF payload (7883BD...). Confirms same NPM publisher (herbsobering) as atomic-lockfile.
- **Relevant for:** Wave 2 package verification.

### 2.4 IFIN Discourse — Full Incident Summary & Updates
- **URL:** https://discourse.ifin.network/t/400-aur-packages-compromised-with-infostealer-and-rootkit/577
- **Date:** 2026-06-11 (updated Jun 12)
- **Content:** Comprehensive attack summary. Links to all major sources. Updated to include js-digest/bun wave. Corrected arojas impersonation note.
- **Relevant for:** Meta-summary, cross-referencing.

### 2.5 Attacker GitHub Container — herbsobering
- **URL:** https://github.com/fardewoak/nodejs-argo/pkgs/container/herbsobering430
- **Date:** 2026-06-11
- **Content:** GitHub Container Registry package tied to attacker. Reverse shell/proxy tool.
- **Relevant for:** Attacker infrastructure, C2.

---

## 3. Mailing List — aur-general

All threads on https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/

### 3.1 Attack Reports & Account Identification

#### 3.1.1 Main Thread — AUR REPORT THREAD
- **URL:** https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/FGXPCB3ZVCJIV7FX323SBAX2JHYB7ZS4/
- **Date:** 2026-06-11 — ongoing
- **Participants:** Andre Herbst (original ~408 package list), Rafal Lichwala, Nicolas Boichat, Damien, Jonathan Grotelüschen (HedgeDoc), many others
- **Content:** Master thread. Initial discovery and scope assessment. Package list expanded over time.
- **Relevant for:** Scope, primary community coordination.

#### 3.1.2 ALVR — First Report
- **URL:** https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/2LGBF2AZBPVCCY4VTN6DOVUNNBURFJ2J/
- **Date:** 2026-06-11
- **Author:** Kusoneko
- **Content:** First public report of suspicious commit on the `alvr` package. Triggered investigation.
- **Relevant for:** Initial discovery timeline.

#### 3.1.3 js-digest Wave — custodiatovar & veramagalhaes
- **URL (thread):** https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/LB6TBHDXLQRPR4UVIQULCI6MZ77XYLL2/
- **Date:** 2026-06-12
- **Participants:** Cedric Girard, ValdikSS, Marcin Wieczorek, Thorsten Wißmann
- **Content:** First report of bun/js-digest wave (guiscrcpy, netmon-git). Identification of **custodiatovar** (13 packages) and **veramagalhaes** (13 packages including inadyn-mt, nodejs-elm). Commit forgery proof for nodejs-elm.
- **Relevant for:** Wave 2 attacker accounts.

#### 3.1.4 Malicious Users — franziskaweber, tobiaswesterburg, ellenmyklebust
- **URL:** https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/LVYB62N3FPAWUHNJ5Z5GXG6OIR7S5P3F/
- **Date:** 2026-06-11, 17:31 UTC
- **Author:** Fabio Loli
- **Content:** Reports three AUR accounts (franziskaweber, tobiaswesterburg, ellenmyklebust) with malicious packages doing "npm shenanigans".
- **Relevant for:** Wave 1 attacker accounts.

#### 3.1.5 Few More Malicious Packages — Package Report
- **URL:** https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/CIKQJQI3AREXIR6IQVWPBYFJPYLM45EF/
- **Date:** 2026-06-11, 20:15 UTC
- **Author:** Sasha Moak
- **Content:** Reports additional suspicious packages (android-support-repository, monochrome, blinkenlib, perl-set-object) all doing npm-based payloads.
- **Relevant for:** Expanded package list.

#### 3.1.6 André Herbst — git-grep Evidence for the Full Package List
- **URL:** https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/message/ALAZHW5PJJUJTT5ICIHDXB6AKSICZ6MA/
- **Date:** 2026-06-11
- **Author:** André Herbst (same author as the original ~408 package list referenced in 3.1.1)
- **Content:** Reply to Jonathan Grotelüschen's request to send found packages back to the thread. Herbst cloned the read-only GitHub mirror of the entire AUR (`archlinux/aur.git`) and ran `git grep 'atomic-lockfile'` across every remote ref, then posted the full per-package result inline — each line in the form `<pkgname>:<pkgname>-deps.install:  npm install atomic-lockfile <decoy packages>` (or a `.hook`/`install.sh` variant of the same pattern). This is the actual forensic evidence behind the aggregate package list, not just a name on a crowd-sourced roll call — it mechanically confirms, per package, that the malicious install line was genuinely present in that package's AUR git history at scan time.
- **Relevant for:** Per-package verification, not just aggregate scope. Confirms `vidcutter` specifically: `vidcutter:vidcutter-deps.install:  npm install atomic-lockfile uuid commander ansi-colors`. Also explains why `package_list.txt` legitimately holds far more than the "400+" cited in the official announcement (1.1) — this single message's git-grep dump alone spans well past 408 names.

### 3.2 Monitoring & Investigation

#### 3.2.1 Likely Malicious Account: ivonahruskova
- **URL:** https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/NCLGU23LSLOFXMBGG7HH67EWDZC2TJB3/
- **Permalink:** https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/message/NCLGU23LSLOFXMBGG7HH67EWDZC2TJB3/
- **Date:** 2026-06-13, 01:25 UTC
- **Author:** Joom
- **Content:** Account created June 11. Adopted 16 packages (vbam-git, mingw-w64-geos, etc.). No malicious commits found yet — flagged for monitoring.
- **Relevant for:** Potentially emerging threat.

#### 3.2.2 Possible Bad Actor: simongeisler
- **URL:** https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/K2ZO3U4WPV7BBT2WAP5P54F23A37RUPH/
- **Permalink:** https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/message/K2ZO3U4WPV7BBT2WAP5P54F23A37RUPH/
- **Date:** 2026-06-12, 18:48 UTC
- **Author:** Paul (aur at hpminc.com)
- **Content:** Account 3 days old, adopted 16 orphaned packages. Suspicious pattern. No malicious commits yet.
- **Relevant for:** Potentially emerging threat.

### 3.3 Proposals & Community Discussion

#### 3.3.1 Proposal: Compile Affected Commit Hashes + Date Ranges
- **URL:** https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/WJ5CH64QMWSFGIJYFSRVEFLSNI7JSKPR/
- **Date:** 2026-06-13
- **Author:** (per list overview)
- **Content:** Proposal to compile per-package commit hashes and date ranges for forensic tracking.
- **Relevant for:** Forensics, detection improvement.

#### 3.3.2 Proposal: Make AUR Read Only
- **URL:** https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/WS2K2XGMLPBFZ3WGOPLF2UP32HZJ6ZSP/
- **Date:** 2026-06-13
- **Participants:** 16 participants
- **Content:** Community discussion about making AUR read-only as a security measure. Preceded the official Arch announcement implementation.
- **Relevant for:** Policy discussion, community sentiment.

#### 3.3.3 Idea for Preventing Malicious Packages
- **URL:** https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/7QZREKFQX3P3UOQNUYJOXANPK4PFH733/
- **Date:** 2026-06-12
- **Content:** General discussion about preventive measures against malicious AUR packages.
- **Relevant for:** Long-term mitigation ideas.

#### 3.3.4 AURSCAN — LLM-Based Pre-Install Scanner
- **URL (main):** https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/E26JEFVSR6YG4GBQUZYDMWYCXD7S7N5V/
- **URL (sub 1):** https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/E2U6G3I5R3RUROVJQINZ2LHOSWVOU4ZI/
- **URL (sub 2):** https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/LLX2Y5DGBXLJUW54ACAFNM26222XFRF6/
- **Date:** 2026-06-13
- **Author:** Andreas Reichel
- **Project:** https://github.com/manticore-projects/aurscan
- **Participants:** Andreas Reichel, Nicolas Boichat (Haiku POC), Oskar Roesler (locally tested Qwen2.5-Coder-7B), Ralf Mardorf
- **Content:** Proposal for an LLM-based AUR package scanner. YAY wrapper sending PKGBUILD files to Claude LLM. Community discussion of alternatives (local models, Haiku-based POC at https://gist.github.com/drinkcat/6a5e632583c67dadf84d68d339cdf799). Successful local tests with Qwen2.5-Coder-7B-Q8_0-GGUF (<5s/package, ~8GB VRAM).
- **Relevant for:** Tooling, LLM-based detection approaches.

---

## 4. Community Detection Scripts

### 4.1 Kidev (Original)
- **URL:** https://gist.github.com/Kidev/59bf9f5fb53ab5eee99f19a6a2fc3992
- **Content:** Foundation: initial package list (~446), basic `pacman -Qi` check loop.

### 4.2 BrianCArnold (Fork)
- **URL:** https://gist.github.com/BrianCArnold/beb514ffc95a9a251b0dc2f767471fca
- **Content:** Efficiency improvement: `pacman -Qm` piped through grep.

### 4.3 commonsourcecs (Fork)
- **URL:** https://cscs.pastes.sh/aurvulntest20260611.sh
- **Content:** Batch `pacman -Qmq` query, install date window (Jun 9–12), expanded package list (~588).

### 4.4 Kacper-Kondracki (Fork)
- **URL:** https://gist.github.com/Kacper-Kondracki/88c5b313f79cc1f9c347e7ed61a36d10
- **Content:** Historical pacman.log scanning with compressed file support, configurable date window via env vars.

### 4.5 quantenProjects (Fork)
- **URL:** https://gist.github.com/quantenProjects/3f768dce7331618310f016d975bf8547
- **Content:** Safe non-executable package list, `comm -1 -2` one-liner approach.

### 4.6 IRC Package List
- **URL:** https://gr.ht/aur_pkg_list.txt
- **Content:** Additional compromised packages collected from IRC.

---

## 5. Impersonation Clarification

### 5.1 arojas — Initial Report
- **URL:** https://infosec.exchange/@mttaggart/116735530761603752
- **Date:** 2026-06-12
- **Author:** mttaggart (IFIN)
- **Content:** Initial report raising arojas question. Later corrected.

### 5.2 arojas — Confirmed Impersonation
- **URL:** https://chaos.social/@dvzrv/116736017948300691
- **Date:** 2026-06-12
- **Author:** David Runge (dvzrv) — Arch Linux TU
- **Content:** Confirms arojas is legitimate KDE maintainer. Attacker reused his identity via git commit forgery. Requests corrections.
- **Relevant for:** Status clarification, "commitforgery".

---

---

## 6. Earlier Malware Campaigns

### 6.1 CHAOS RAT AUR Incident

- **URL:** https://linuxsecurity.com/features/chaos-rat-in-aur
- **Date:** 2025-07-22
- **Author:** Linux Security
- **Content:** Documents malicious AUR packages distributing the CHAOS RAT remote access trojan through modified PKGBUILDs.
- **Relevant for:** Historical AUR malware campaign and package attribution.

**Confirmed malicious packages:**

- `librewolf-fix-bin`
- `firefox-patch-bin`
- `zen-browser-patched-bin`

---

### 6.2 Public Reporting of the Incident

- **URL:** https://itsfoss.com/news/arch-linux-chaos-rat/
- **Date:** 2025-08-04
- **Author:** Sourav Rudra (It's FOSS)
- **Content:** Summarizes the AUR incident involving malicious packages distributing CHAOS RAT and documents package removal by Arch maintainers.
- **Relevant for:** Independent reporting and timeline confirmation.

---

### 6.3 Community Discussion and Additional Packages

- **URL:** https://discuss.privacyguides.net/t/security-firefox-patch-bin-librewolf-fix-bin-and-zen-browser-patched-bin-aur-packages-contain-malware/29232
- **Date:** 2025-07
- **Author:** Privacy Guides Community
- **Content:** Community discussion documenting additional packages associated with the incident.
- **Relevant for:** Community-reported package attribution.

**Community-reported packages:**

- `vesktop-bin-patched`
- `minecraft-cracked`
- `ttf-ms-fonts-all`
- `ttf-all-ms-fonts`

---

## 7. Example Malicious Commit

- **URL:** https://aur.archlinux.org/cgit/aur.git/commit/?h=premake-git&id=232b22dd0aaedfa9fde1800710e0d52e4f4b542d
- **Date:** 2026-06-09
- **Content:** Concrete example of a malicious PKGBUILD commit showing the injected npm install payload.
- **Relevant for:** Attack vector illustration.

---

## 8. Russian Spam Campaign (Separate from JS Supply-Chain)

### 8.1 Initial Report
- **URL:** https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/message/2YQSHTC27MOKDDKHZTH2BJGTEN2CYC7W/
- **Date:** 2026-06-14, 18:03 UTC
- **Author:** Sid Karunaratne
- **Content:** 73+ AUR packages with PKGBUILD modifications injecting Russian spam echo statements into ~/.bashrc, ~/.zshrc at install time. Full package list extracted in `malicious_russian_spam_packages.txt`.
- **Detection method:** `git grep --files-with-matches 'NoServices'` across all AUR remote refs.
- **Status:** Reported to Arch DevOps, cleanup in progress.
- **Relevant for:** Independent threat vector requiring separate detection patterns (shell config injection ≠ JS package manager detection).

---

## 9. aur-audit.wtako.net Feed

- **URL:** https://wtako.net/services/aur-audit
- **API docs:** https://wtako.net/services/aur-audit/docs
- **Author:** An independent, pseudonymous individual operator ("Saren" / wtako.net — personal homelab site, not a security vendor or organization). Third-party, unaffiliated with archcanary.
- **Content:** Free, unauthenticated JSON API publishing continuous automated scan verdicts for AUR packages, categorized black (confirmed malicious), red (high-risk), and yellow (minor/qualitative). Paginated via `GET /packages?filter=black|red&before=&limit=`.
- **Detection method:** `--refresh` pages through the `black` and `red` filters and stores the package names in `aur_audit_black.txt`/`aur_audit_red.txt`. Yellow is intentionally not synced — too noisy for an automated check without incident history to justify it.
- **Status:** Live, continuously updated by the upstream service — not a static snapshot.
- **Trust basis:** Neither the site nor the API docs publish a scanning methodology, source code, or a track record — there are no operator credentials to verify. Included anyway because the integration itself is low-risk: the API is free, unauthenticated, and read-only; its hits are merged as an annotated, attributable signal (`[aur-audit: black]`/`[aur-audit: red]`) alongside archcanary's own sourced/cited lists rather than replacing them. This is unlike every other entry in this file, which are all independently corroborated incident reports — treat this one as a best-effort community signal, not verified intelligence.
- **Relevant for:** Community-scale, continuously-updated denylist supplementing archcanary's own hand-curated lists.

---

## 10. Community Reports

- **File:** `lists/community_reports.txt`
- **Maintainer:** musqz, directly in this repo.
- **Content:** Individually-reported AUR packages that don't (yet) belong to a documented campaign — sourced from community reports (mailing lists, forums, direct reports) as they come in. No fixed scope or end date, unlike the campaign-specific lists above.
- **Detection method:** `--refresh` fetches it like the other supplementary lists; hits are annotated `[community report]`.
- **Status:** Ongoing, updated as reports come in.
- **Trust basis:** Same caveat as the aur-audit feed above — this is best-effort curation from unverified community reports, not independently corroborated incident data like sections 1-8. A package landing here means "reported as suspicious by someone in the community", not "confirmed malicious with a public writeup". `--check-list-overlap` deliberately doesn't require entries here to be deduplicated against the other official lists before being added — overlap is harmless once a package is in an official list.
- **Relevant for:** Catching AUR malware between documented campaigns, before it's significant enough for its own writeup.

---

## 11. Second Wave — July 2026 Package Adoption Attack

A separate, later campaign from the June 2026 atomic-lockfile/js-digest attack (sections 1-8 above) — same attacker infrastructure signature, different vector (malicious package *adoption* + follow-up commits, rather than a fresh supply-chain payload).

### 11.1 Robin Candau — AUR Package Adoption Disabled
- **URL:** https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/message/DRDEU3JUSC72CB265XHXPFA3DFSLXPBP/
- **Date:** 2026-07-30, 16:22 UTC
- **Author:** Robin Candau (Antiz), Arch Linux DevOps team
- **Content:** Announces AUR package adoption disabled "due to the current influx of malicious package adoptions and follow-up commits." No package names given — just the containment measure and a request for the community to report suspicious adoptions/commits.
- **Relevant for:** Official response timeline, containment measure.

### 11.2 IFIN — New AUR Attack Prompts Adoption Lock
- **URL:** https://discourse.ifin.network/t/new-aur-attack-prompts-adoption-lock/698
- **Date:** 2026-07-30, updated 2026-07-31
- **Author:** mttaggart (IFIN) — same author as section 5.1
- **Content:** First confirmed package: `openconnect-sso` (dropper in the `build()` phase, hit from ~2026-07-29; offending commit since reverted, binary reportedly still reachable as a deeplink). Same Tor-based C2 exfil signature as the June campaign — SHA256 hashes for both payload stages, a `.onion` C2 address, a systemd-service-name persistence pattern, and a macOS LaunchDaemon pattern (`.com.apple.telemetry.<random>`). Explicitly not a closed incident as of the last update: "new malicious commits were still being discovered." Recommends blocking Tor egress and cross-checking installed packages against the aur-audit.wtako.net feed (section 9).
- **Relevant for:** First named package, technical IOCs, explicit confirmation the scope isn't finalized.

### 11.3 Tracking Issue — Upstream Project
- **URL:** https://github.com/lenucksi/aur-malware-check/issues/52
- **Date:** Opened 2026-07-30
- **Content:** "Malware in openconnect-sso hit from 29th July 2026" — tracking issue on the original project archcanary forked from, linking the two aur-general threads below and the offending AUR commit directly.
- **Relevant for:** Cross-reference to the original malware-check project's own tracking.

### 11.4 Related aur-general Threads
- https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/PR77K3SB6RFSTYP3KYOJOOX56SMXGBWO/
- https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/PMATLG676MPBWUJPZZ75WJ4H3BKE7TVL/
- **Relevant for:** Original community reports that led to 11.2's writeup.

### 11.5 FOSS Force — Public Reporting
- **URL:** https://fossforce.com/2026/07/new-attack-puts-archs-aur-into-lockdown-again/
- **Date:** 2026-08-01
- **Author:** Christine Hall
- **Content:** Independent public coverage, ties together 11.1/11.2 plus LWN.net's report (Joe Brockmeier) and the June incident's containment timeline (seeded ~June 12, contained June 16 via registration blocking, reopened July 13 with "minor, apparently ineffective" restrictions before this second wave). Also gives a higher total for the June campaign than section 1.1's initial announcement: "more than 1,500 infected packages" by the time it was fully contained — the count grew past the day-one "400+" figure as cleanup continued.
- **Relevant for:** Independent corroboration, revised June-campaign total, public timeline.

### 11.6 `openconnect-sso` in archcanary
- **Added to:** `lists/community_reports.txt` (2026-08-02), annotated `[community report]` on hit.
- **Why here and not a dedicated campaign list:** as of 11.2's last update the full scope of this wave isn't known yet — a single confirmed package fits the Community Reports list's stated purpose (11 above) better than a new campaign-specific list, which would imply a settled, bounded scope this wave doesn't have yet. Revisit if/when this wave gets its own confirmed package count and closure, the way the June campaign did.
