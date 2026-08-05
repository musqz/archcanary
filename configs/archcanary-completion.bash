# bash completion for archcanary / canary
# Installed by install.sh / the AUR package into a bash-completion
# completions/ directory (system or user) where it loads automatically.
#
# Also registered for archcanary.sh / ./archcanary.sh: bash's programmable
# completion looks up a spec by the exact literal first word typed on the
# command line, so running the script straight from a repo checkout
# (./archcanary.sh --a<TAB>) matched no spec at all and silently fell back
# to default filename completion — registering under just "archcanary" and
# "canary" only ever covered the installed binary. This completion file
# isn't auto-loaded for a repo checkout (it's only installed into the
# bash-completion completions/ dir by install.sh/the package) — source it
# manually first: `source configs/archcanary-completion.bash`.

_archcanary() {
    local cur prev words cword split
    if declare -F _init_completion >/dev/null; then
        _init_completion -s || return
    else
        cur="${COMP_WORDS[COMP_CWORD]}"
        prev="${COMP_WORDS[COMP_CWORD-1]:-}"
        split=false
    fi

    case "$prev" in
        --doctor)
            COMPREPLY=($(compgen -W "platform deps user system systemd external all" -- "$cur"))
            return 0
            ;;
        --color)
            COMPREPLY=($(compgen -W "auto always never" -- "$cur"))
            return 0
            ;;
        --format)
            COMPREPLY=($(compgen -W "text json" -- "$cur"))
            return 0
            ;;
        --allowlist-list|--allowlist-add|--allowlist-remove)
            COMPREPLY=($(compgen -W "dkms systemd bpftool autostart" -- "$cur"))
            return 0
            ;;
        --package-list|--malicious-npm-list|--chaos-rat-list|--russian-spam-list|--community-list|--extra-list|--extra-lists-add|--extra-lists-remove|--log-file)
            _filedir
            return 0
            ;;
    esac
    $split && return 0   # e.g. --start-date=, --end-date= — no value completion

    local flags="
        --check-systemd --check-ebpf --check-npm-cache --check-bun-cache
        --check-yarn-cache --check-pnpm-cache --check-pkgbuild --check-bpftool
        --check-ldso --check-autostart --check-kmod --check-lynis
        --check-pkginteg --check-list-overlap --scan-all-homes --search-packages= --full --refresh --no-aur-audit --verbose -v --debug
        --no-notify --no-summary --run-lynis --doctor --version -V --help -h
        --log-file= --package-list= --malicious-npm-list= --chaos-rat-list=
        --russian-spam-list= --community-list= --extra-list= --start-date= --end-date=
        --color= --format= --doctor=
        --allowlist-list= --allowlist-add= --allowlist-remove=
        --extra-lists-list --extra-lists-add= --extra-lists-remove=
        --aur-audit-status --aur-audit-enable --aur-audit-disable
        --audit-rules-get --audit-rules-set --lynis-config-get --lynis-config-set
    "
    COMPREPLY=($(compgen -W "$flags" -- "$cur"))
    return 0
}
complete -F _archcanary archcanary canary archcanary.sh ./archcanary.sh
