# bash completion for archcanary / canary
# Installed by install.sh / the AUR package into a bash-completion
# completions/ directory (system or user) where it loads automatically.

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
        --package-list|--malicious-npm-list|--chaos-rat-list|--russian-spam-list|--extra-list|--log-file)
            _filedir
            return 0
            ;;
    esac
    $split && return 0   # e.g. --start-date=, --end-date= — no value completion

    local flags="
        --check-systemd --check-ebpf --check-npm-cache --check-bun-cache
        --check-yarn-cache --check-pnpm-cache --check-pkgbuild --check-bpftool
        --check-ldso --check-autostart --check-kmod --check-lynis
        --check-pkginteg --full --refresh --no-aur-audit --verbose -v --debug
        --no-notify --no-summary --run-lynis --doctor --version -V --help -h
        --log-file= --package-list= --malicious-npm-list= --chaos-rat-list=
        --russian-spam-list= --extra-list= --start-date= --end-date=
        --color= --doctor=
    "
    COMPREPLY=($(compgen -W "$flags" -- "$cur"))
    return 0
}
complete -F _archcanary archcanary canary
