# Overview — how the stack fits together

A one-screen map of the AUR security stack. For the full reference (every
component, install locations, reinstall steps) see [my-setup.md](my-setup.md).

The whole stack hangs off the **AUR package lifecycle**: checks happen *before*
you install, *at* install time, *after* install (continuously), and *on
detection*.

```mermaid
flowchart TD
    subgraph PRE["1 · BEFORE install — manual"]
        T["traur scan &lt;pkg&gt;<br/>279 heuristic signals"]
    end

    subgraph AT["2 · AT install — automatic (alias yay=syay)"]
        U["yay -S pkg / yay -Syu"] --> SY{"syay / aurscan<br/>static rules + Claude LLM"}
        SY -->|suspicious| AB["build aborted"]
        SY -->|CLEAN| Y["/usr/bin/yay"]
        Y --> LUA["yay init.lua hooks<br/>age warn · pattern block · log"]
        LUA --> OK["package installed"]
    end

    subgraph AFTER["3 · AFTER install / always — automatic, root"]
        TIM["systemd timer<br/>weekly + on boot"] --> SCAN["archcanary<br/>--full --all-time"]
        PTH[".path unit<br/>after each pacman tx"] --> SCAN
        SCAN --> LOG["last-scan.log"]
    end

    subgraph ALERT["4 · ON detection / review"]
        LOG -->|INFECTED| NOT["user .path → notify-send<br/>critical desktop alert"]
        NOT --> GUI["archcanary-gui<br/>review + root checks"]
    end

    T -.->|install if trusted| U
    OK -.-> PTH
```

## At a glance

| Phase | Tool | Trigger | Automatic? | Catches |
|-------|------|---------|:---------:|---------|
| 1 · Before | `traur scan <pkg>` | You run it before installing | ✗ manual | Maintainer reputation, PKGBUILD heuristics (279 signals) |
| 2 · At install | `syay` / `aurscan` | Every `yay` call (`alias yay=syay`) | ✓ | Novel / obfuscated payloads — Claude reads the PKGBUILD |
| 2 · At install | yay `init.lua` hooks | After aurscan clears the build | ✓ | Known campaign signatures, stale-rewrite upgrades (offline) |
| 3 · After / always | `archcanary` | systemd timer (weekly + boot) + `.path` (after each pacman tx) | ✓ root | Known-bad packages, systemd/eBPF/npm persistence, rootkit traces |
| 4 · On detection | notifier → GUI | `last-scan.log` flips to INFECTED | ✓ | Surfaces a result; review is manual |

## Read this first

- **Nothing here removes malware.** Every layer *detects and reports* — remediation is left to you. See [Read-only by design](../README.md).
- **Pre-install vs post-install.** Phases 1–2 try to stop a bad package before it lands; phase 3 catches anything already installed (or installed before the stack existed).
- **Defence in depth.** The LLM (aurscan) catches the novel; the offline Lua hooks catch the known and run even with no network; `traur` adds maintainer/metadata signals no static scan sees. None replaces the others.

## Go deeper

| Want… | See |
|-------|-----|
| Every component + how it's wired | [my-setup.md](my-setup.md) |
| systemd unit file contents | [systemd.md](systemd.md) |
| Benign signals that fire anyway | [false-positives.md](false-positives.md) |
