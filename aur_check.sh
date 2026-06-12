#!/usr/bin/env bash
#
# aur_check.sh - Consolidated AUR Malware Check Script
# Campaign: June 2026 - atomic-lockfile infostealer + eBPF rootkit
#
# Combines best features from all community forks:
#   - Kidev (original):         package list foundation
#   - BrianCArnold (fork):      pacman -Qm efficiency
#   - commonsourcecs (fork):    batch query + date window check
#   - Kacper-Kondracki (fork):  pacman.log scanning + compressed logs
#   - quantenProjects (fork):   safe comm-based approach
#
# Also checks for:
#   - systemd persistence artifacts
#   - eBPF rootkit traces (/sys/fs/bpf/hidden_*)
#   - atomic-lockfile npm cache presence
#
# Usage:
#   ./aur_check.sh                    # normal check
#   ./aur_check.sh --check-systemd    # also scan systemd for unknown services
#   ./aur_check.sh --check-ebpf       # also check for eBPF rootkit traces
#   ./aur_check.sh --check-npm-cache  # also check npm cache for atomic-lockfile
#   ./aur_check.sh --full             # enable all checks
#
# Environment:
#   START_DATE=2026-06-09  END_DATE=2026-06-12  ./aur_check.sh
#   PACMAN_LOG_GLOB="/var/log/pacman.log*"       ./aur_check.sh
#
# Exit codes:
#   0 = clean
#   1 = warnings (e.g. log scan issues)
#   2 = infected packages found
#
# Sources:
#   https://gist.github.com/Kidev/59bf9f5fb53ab5eee99f19a6a2fc3992
#   https://gist.github.com/BrianCArnold/beb514ffc95a9a251b0dc2f767471fca
#   https://cscs.pastes.sh/aurvulntest20260611.sh
#   https://gist.github.com/Kacper-Kondracki/88c5b313f79cc1f9c347e7ed61a36d10
#   https://gist.github.com/quantenProjects/3f768dce7331618310f016d975bf8547

set -euo pipefail

SCRIPT_VERSION="1.0.0"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
START_DATE=${START_DATE:-2026-06-09}
END_DATE=${END_DATE:-2026-06-12}
PACMAN_LOG_GLOB=${PACMAN_LOG_GLOB:-/var/log/pacman.log*}

CHECK_SYSTEMD=false
CHECK_EBPF=false
CHECK_NPM_CACHE=false
VERBOSE=false

for arg in "$@"; do
    case "$arg" in
        --check-systemd) CHECK_SYSTEMD=true ;;
        --check-ebpf)    CHECK_EBPF=true ;;
        --check-npm-cache) CHECK_NPM_CACHE=true ;;
        --full)          CHECK_SYSTEMD=true; CHECK_EBPF=true; CHECK_NPM_CACHE=true ;;
        --verbose|-v)    VERBOSE=true ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  --check-systemd    Scan for unknown systemd services (Restart=always)"
            echo "  --check-ebpf       Check for eBPF rootkit traces (/sys/fs/bpf/hidden_*)"
            echo "  --check-npm-cache  Check npm cache for atomic-lockfile"
            echo "  --full             Enable all checks"
            echo "  --verbose, -v      Verbose output"
            echo "  --help, -h         Show this help"
            exit 0
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Package list - consolidated from all sources
# Sorted alphabetically for easy diff with package_list.txt
# ---------------------------------------------------------------------------
INFECTED_PKGS=(
123pan-bin 1code 8192eu-dkms-git actual-ai adblock2privoxy aion-git
albion-online-launcher-bin alienfx alvr android-signapk android-signapk-gui
android-support-repository annobin ansible-language-server antfs-cli-git
anythingllm-appimage anythingllm-cli-bin apk-installer-gui apm_planner-bin
apothem apple-music-desktop arch-update-vai archjh archlinux-themes-slim
archmage archtex-git arm-linux-gnueabihf-binutils artanis-git
astro-editor-appimage autohand-cli autolabel autologin azurlaneautoscript
bcachefs-kernel-dkms-git beebeep bitcoin-core-git blinkenlib
blueproximity-py3-git booklore brow6el brow6el-git
canon-pixma-mg3000-complete-fixed cartridge-cli ccase-bin ccl-git cgminer
charcoal cinny-desktop-system-tray clai clang19 clash-mi cling-git
cmuclmtk cnijfilter-common codenomad-bin codeql-cli-bin cogpit-bin
colorhug-client colorz compiler-rt19 compizconfig-python coolreader cowdancer
cutefish-calculator cutefish-core cutefish-dock cutefish-filemanager
cutefish-icons cutefish-launcher cutefish-qt-plugins cutefish-screenlocker
cutefish-screenshot cutefish-settings cutefish-statusbar cutefish-wallpapers
cvs-feature-bin cynthiune.app dagu-bin datatype99 deheader dep dh-python
difi difi-bin doctoc dots-hyprland-fork-git dvdrip dyad-bin easy_spice
edconv-bin efiboots-git electrum-nmc elmerfem eisl
epson-inkjet-printer-escpr2-clos-bin exodus-wallet-bin exoduswallet
farmmod-hub fastoggenc fastjet fatx fcitx5-pinyin-sougou-dict-git
ffmpeg-bitrate-stats ffmpeg-quality-metrics findpkg-git
firefox-extension-adnauseam-bin-amo firmium-desktop-git fishui fishui-git
flashfocus flexiblas flynarwhal fmlib forgecode-bin formidable-bin frame
ftl frutool futhark-bin gdl gdlmm git-annex-standalone gnome-contacts-git
gnome-randr-rust gnutls3.8.9 gopher2600 gopher2600-bin gosh gpx-viewer
graveman green-tunnel-bin greetd-wlgreet-git gtkimageview guile-reader gummy
gummy-git hackmatrix-git harmony-wad headphones hearthstone-linux-gui-appimage
hearthstone-linux-gui-bin hepmc2 hister-git hnswlib-git horst
hydownloader-git hydrus-git i3bar-river ianny-bin ibm-sw-tpm2 ihaskell-git
imageglass inadyn indicator-session infnoise-openssl-git interface99
ios-webkit-debug-proxy ipfs-desktop-bin ipsw iron-heart-git jasp-desktop jd-gui
k3sup kdb kddockwidgets-git kexi kiss ktea kookbook kproperty kreport
latex-digsig lazylpsolverlibs-git ledger-udev-bin lesstif lib32-egl-wayland
libafterimage libbobcat libcutefish libffi-static libgdata libjxl-noglycin
libquvi libquvi-scripts libretro-hatari-enhanced-git libxdiff libxml-ruby
libyami linux-cachyos-deckify-native linux-cachyos-deckify-native-headers
linux-cachyos-native linux-cachyos-native-headers linux-cachyos-native-nvidia-open
linux-cachyos-rc-native linux-cachyos-rc-native-headers
linux-cachyos-rc-native-nvidia-open linux-tool liri-cmake-shared-git lite lll
llvm-cbe-git lowfi-bin ls++ lucidvideo m5rcode magpie-wm mako-center-git
manuskript maszyna-git mathsat-5 matrixbrandy mcp-probe mcpatcher
mermaid-ascii-git mermark-editor mesa-dlss-reflex-git meteo mimic-node-git
mingw-w64-geos mingw-w64-libsndfile minimax-bin-hardened minitube
misuzu-music-bin mono-addins monochrome monochrome-git moor-git mount-gtk mopen
n1-translator naemon naemon-livestatus natapp nebuchadnezzar-git
neovim-autopairs-git neovim-nvim-treesitter nerf-pi neuro-karaoke-wrapper-git
new-api-privacy-filter new-api-privacy-filter-git nextcloud-app-audioplayer
nextcloud-app-facerecognition nextcloud-app-gpoddersync
nextcloud-app-integration-google nextcloud-app-repod
nextcloud-app-twofactor-gateway nextcloud-git nexus-bin nginx-mod-vts
nhentai-git nocodb noctyra-dotfiles-git noctyra-meta-git notepad---bin nox-bin
nrpe nwchem-bin ob-xd octocode opencode-codebase-index-bin openui5 opl-synth
optimizevideo-git oracle-bin pacforge paper-desktop-bin paq8o parallel-python
pass-cli pelican-git penguin-subtitle-player perl-proc-parallelloop
perl-set-object perl-term-extendedcolor phonon-qt5-vlc php-geoip
php-legacy-memcache php-memcache php-openswoole-git php-xdiff picom-ftlabs-git
pidgin-kwallet pipetoys pipewire-visualizer-git plex-media-player-custom
plex-media-player-mod plex-media-player-v2 premake-git prisma4postgres-bin
profile-sync-daemon-zen pymacs pypiserver pypy-setuptools python-apt
python-affine python-argdispatch python-awkward python-axolotl-git python-calmjs
python-celery python-cerealizer python-ci-info python-coolname python-cu2qu-git
python-dataproperty python-dbapi-compliance python-dictobject
python-dj-database-url python-django-modelcluster python-django-rest-knox
python-fastmcp-slim python-finnhub-python python-firebase-admin
python-fmu_manipulation_toolbox python-future python-g4f python-hist
python-histoprint python-hsaudiotag3k python-iminuit python-iso3166
python-isr-git python-jsmin python-json2xml python-luckydonald-utils
python-milvus-lite-bin python-mmcif python-monotonic python-mplhep
python-mplhep_data python-netaudio-git python-netaudio-lib python-newspaper4k
python-nipype python-nodejs-wheel python-openai-harmony python-orange
python-pdf2docx python-piecash python-pluginmgr python-poetry-plugin-dotenv
python-privy-git python-pushbullet.py python-pychromecast-git python-pylsp-rope
python-pymilvus python-pysocks-git python-rembg python-scikit-hep-testdata
python-sklearn-pandas python-sqliteschema python-starlette-compress
python-starsessions python-steamcontroller-git python-tabledata python-tarantool
python-tradingeconomics python-uhi python-uproot python-vector python-xtarfile
python2-appdirs python2-fusepy python2-lazr-uri python2-mutagen python2-notify
python2-packaging python2-paver python2-pyparsing python2-simplejson
python2-simpleparse python2-stomper python2-twodict-git python2-xlib qhttpengine
qlementine qmdnsengine qnapi qobuz-player-bin qtum-core quickswitch-i3 r-dbplyr
reactphysics3d repoporge retibbs-client-git rhythmbox-git rimworld rog-helper-git
ros2-humble-nav2-msgs rtspeccy-git ruah-orch ruby-excon ruby-kramdown-rfc2629
ruby-selenium-webdriver runescape-launcher sakura-launcher-gui sandlock
screenpipe-bin sdcc-bin seahorse-nautilus shhmsg shhopt slipnet slipnet-bin smenu
smenu-git smolrtsp smolrtsp-libevent snry-shell-qs soapyptezuka
solara-kernel-headers sonosano soundpaad-bin sshuttlee sshuttlee-bin
stompbox-jack-git stripe-cli stylelint-config-recommended subbrute sublist3r-git
subprocess subsync svu sway-xkb-switcher tack tarantool tesseract-gui
thunar-nextcloud-plugin thunderbird-conversations tinyemu tlpui-git torch7-git
touchhle touchosc-bin transcreen tsm ttf-material-design-icons-git tunacode-cli
typing-game-cli ukui-notification-daemon vapoursynth-preview-git vbam-git
verso-git vidcutter vim-easymotion vim-gitgutter vim-indent-object vim-molokai
vim-pythonhelper vim-solidity vim-vital vocalinux-git voquill-gpu
wallpaper-generator-next wayland-static we-layerd-git whatsie-git whisper2tr
whisper2tr-git windowmaker-git wine-nine wire-desktop word-snatchers-cli
workbench workbuddy-bin wrystr-git wsjtx-beta xf86-input-mtrack-git xorg-xfsinfo
xplot xpra-html5 xray-domain-list-community yarg yt6801-dkms yy
zathura-gruvbox-git zerx-lab-dida-bin zerx-lab-zed-nightly-bin zing-8-bin
zing-17-bin zing-21-bin zinnia-python zsdx
)

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
log_info()  { echo "[INFO] $*"; }
log_warn()  { echo >&2 "[WARN] $*"; }
log_found() { echo >&2 "[FOUND] $*"; }

date_in_window() {
    local date_val=$1
    [[ "$date_val" < "$START_DATE" ]] && return 1
    [[ "$date_val" > "$END_DATE" ]] && return 1
    return 0
}

install_date_in_window() {
    local raw_date=$1 normalized
    normalized=$(LC_ALL=C date -d "$raw_date" +%F 2>/dev/null) || return 1
    date_in_window "$normalized"
}

read_compressed_file() {
    local file=$1
    case "$file" in
        *.gz)   gzip -cd -- "$file" 2>/dev/null ;;
        *.xz)   xz -cd -- "$file" 2>/dev/null ;;
        *.zst)  zstdcat -- "$file" 2>/dev/null ;;
        *.bz2)  bzip2 -cd -- "$file" 2>/dev/null ;;
        *)      cat -- "$file" ;;
    esac
}

print_list() {
    local -n arr=$1
    for item in "${arr[@]}"; do echo "  - $item"; done
}

# ---------------------------------------------------------------------------
# Check 1: Currently installed foreign packages
# (Efficiency from commonsourcecs: pacman -Qmq in batch)
# ---------------------------------------------------------------------------
check_current() {
    local found=()
    while IFS= read -r pkg; do
        local install_date
        install_date=$(LC_ALL=C pacman -Qi -- "$pkg" 2>/dev/null | awk -F': ' '/^Install Date/ { print $2; exit }')
        if [[ -n "$install_date" ]] && install_date_in_window "$install_date"; then
            found+=("$pkg (installed: $install_date)")
        fi
    done < <(pacman -Qmq "${INFECTED_PKGS[@]}" 2>/dev/null)

    if [[ ${#found[@]} -eq 0 ]]; then
        echo "  Clean: no infected packages installed within campaign window."
        return 0
    else
        echo "  WARNING: ${#found[@]} possibly infected package(s):"
        print_list found
        return 2
    fi
}

# ---------------------------------------------------------------------------
# Check 2: Historical pacman logs
# (From Kacper-Kondracki: scan pacman.log* for install events)
# ---------------------------------------------------------------------------
check_logs() {
    local log_files=() found=() warnings=()

    for file in $PACMAN_LOG_GLOB; do
        [[ -e "$file" ]] && log_files+=("$file")
    done

    if [[ ${#log_files[@]} -eq 0 ]]; then
        log_warn "No pacman log files matched: $PACMAN_LOG_GLOB"
        return 1
    fi

    local tmpfile
    tmpfile=$(mktemp)
    printf '%s\n' "${INFECTED_PKGS[@]}" > "$tmpfile"

    for file in "${log_files[@]}"; do
        [[ -r "$file" ]] || { warnings+=("Skipped $file: not readable"); continue; }
        read_compressed_file "$file" | while IFS= read -r line; do
            local date_str action pkg
            date_str=$(echo "$line" | sed -n 's/^\[\([0-9-]*\).*/\1/p')
            [[ -z "$date_str" ]] && continue
            date_in_window "$date_str" || continue

            action=$(echo "$line" | sed -n 's/.*\[ALPM\] \([a-z]*\) .*/\1/p')
            pkg=$(echo "$line" | sed -n 's/.*\[ALPM\] [a-z]* \([^ ]*\).*/\1/p')
            [[ -z "$action" || -z "$pkg" ]] && continue

            if grep -qxF "$pkg" "$tmpfile" 2>/dev/null; then
                if [[ "$action" == "installed" || "$action" == "upgraded" || "$action" == "reinstalled" ]]; then
                    echo "LOG_HIT: $pkg ($action on $date_str)"
                fi
            fi
        done || true
    done

    rm -f "$tmpfile"
}

# ---------------------------------------------------------------------------
# Check 3: systemd persistence artifacts
# (Original addition: look for services with Restart=always + RestartSec=30)
# ---------------------------------------------------------------------------
check_systemd() {
    local found=()
    local dirs=("/etc/systemd/system" "$HOME/.config/systemd/user")

    for dir in "${dirs[@]}"; do
        [[ -d "$dir" ]] || continue
        while IFS= read -r svc; do
            if grep -q 'Restart=always' "$svc" 2>/dev/null && grep -q 'RestartSec=30' "$svc" 2>/dev/null; then
                found+=("$svc")
            fi
        done < <(find "$dir" -name '*.service' -type f 2>/dev/null)
    done

    if [[ ${#found[@]} -gt 0 ]]; then
        echo "  WARNING: ${#found[@]} service(s) with Restart=always + RestartSec=30:"
        print_list found
        return 2
    fi
    echo "  Clean: no suspicious systemd services found."
    return 0
}

# ---------------------------------------------------------------------------
# Check 4: eBPF rootkit traces
# (From ioctl.fail analysis: /sys/fs/bpf/hidden_* maps)
# ---------------------------------------------------------------------------
check_ebpf() {
    if [[ ! -d /sys/fs/bpf ]]; then
        echo "  /sys/fs/bpf not available (BPF not mounted or no privileges)."
        return 0
    fi

    local found=()
    for map in hidden_pids hidden_names hidden_inodes; do
        if [[ -e "/sys/fs/bpf/$map" ]]; then
            found+=("/sys/fs/bpf/$map")
        fi
    done

    if [[ ${#found[@]} -gt 0 ]]; then
        echo "  WARNING: eBPF rootkit traces found:"
        print_list found
        return 2
    fi
    echo "  Clean: no eBPF rootkit traces detected."
    return 0
}

# ---------------------------------------------------------------------------
# Check 5: npm cache for atomic-lockfile
# ---------------------------------------------------------------------------
check_npm_cache() {
    local npm_cache
    npm_cache=$(npm cache ls 2>/dev/null | grep 'atomic-lockfile' || true)
    if [[ -n "$npm_cache" ]]; then
        echo "  WARNING: atomic-lockfile found in npm cache:"
        echo "$npm_cache" | sed 's/^/    /'
        return 2
    fi

    # Also check global node_modules
    local global_mod
    global_mod=$(npm root -g 2>/dev/null)/atomic-lockfile
    if [[ -d "$global_mod" ]]; then
        echo "  WARNING: atomic-lockfile found in global node_modules"
        return 2
    fi

    # Check npm cache folder directly
    local npm_cache_dir
    npm_cache_dir=$(npm config get cache 2>/dev/null)
    if [[ -d "$npm_cache_dir" ]]; then
        local cached
        cached=$(find "$npm_cache_dir" -name '*atomic-lockfile*' -type d 2>/dev/null | head -5 || true)
        if [[ -n "$cached" ]]; then
            echo "  WARNING: atomic-lockfile in npm cache directory:"
            echo "$cached" | sed 's/^/    /'
            return 2
        fi
    fi

    echo "  Clean: no atomic-lockfile traces in npm cache."
    return 0
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
EXIT_CODE=0

echo "============================================================"
echo " AUR Malware Check v${SCRIPT_VERSION}"
echo " Campaign: atomic-lockfile infostealer + eBPF rootkit"
echo " Date window: ${START_DATE} to ${END_DATE}"
echo " Packages checked: ${#INFECTED_PKGS[@]}"
echo "============================================================"
echo

echo "--- [1] Currently installed foreign packages ---"
check_current && ret=$? || ret=$?
[[ $ret -gt $EXIT_CODE ]] && EXIT_CODE=$ret
echo

echo "--- [2] Historical pacman logs ---"
if [[ -f /var/log/pacman.log ]]; then
    check_logs > /tmp/aur_check_logs.tmp 2>&1 || true
    if grep -q 'LOG_HIT' /tmp/aur_check_logs.tmp 2>/dev/null; then
        echo "  WARNING: historical log matches:"
        grep 'LOG_HIT' /tmp/aur_check_logs.tmp | sed 's/LOG_HIT: /  - /'
        [[ 2 -gt $EXIT_CODE ]] && EXIT_CODE=2
    else
        echo "  Clean: no historical log matches found."
    fi
    grep '\[WARN\]' /tmp/aur_check_logs.tmp 2>/dev/null && true
    rm -f /tmp/aur_check_logs.tmp
else
    echo "  Skipped: /var/log/pacman.log not found."
fi
echo

if $CHECK_SYSTEMD; then
    echo "--- [3] Systemd persistence check ---"
    check_systemd && ret=$? || ret=$?
    [[ $ret -gt $EXIT_CODE ]] && EXIT_CODE=$ret
    echo
fi

if $CHECK_EBPF; then
    echo "--- [4] eBPF rootkit check ---"
    check_ebpf && ret=$? || ret=$?
    [[ $ret -gt $EXIT_CODE ]] && EXIT_CODE=$ret
    echo
fi

if $CHECK_NPM_CACHE; then
    echo "--- [5] npm cache check ---"
    check_npm_cache && ret=$? || ret=$?
    [[ $ret -gt $EXIT_CODE ]] && EXIT_CODE=$ret
    echo
fi

echo "============================================================"
case $EXIT_CODE in
    0) echo " RESULT: CLEAN - No indicators found." ;;
    1) echo " RESULT: WARNINGS - Review output above." ;;
    2) echo " RESULT: INFECTED - Indicators found! Follow incident response." ;;
esac
echo "============================================================"

exit $EXIT_CODE
