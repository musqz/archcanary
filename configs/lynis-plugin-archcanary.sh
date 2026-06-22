#!/bin/sh
#################################################################################
#
#   Lynis plugin — archcanary
#   Registers archcanary as an AUR supply chain malware scanner.
#
#   Auto-installed by: archcanary --run-lynis (runs as root via pkexec)
#   Source:            /usr/lib/archcanary/lynis-plugin-archcanary.sh
#
#################################################################################

PLUGIN_AUTHOR="musqz"
PLUGIN_CATEGORY="malware"
PLUGIN_DATE="2026-06-22"
PLUGIN_DESC="Detects archcanary AUR supply chain malware scanner"
PLUGIN_NAME="archcanary"
PLUGIN_REQUIRED_PROFILE="generic"
PLUGIN_MINIMUM_VERSION="3.0.0"
PLUGIN_VERSION="1.0"

InsertSection "Archcanary (AUR supply chain scanner)"

Register --test-no ARCH-0001 --weight L --network NO --category security \
    --description "Check for archcanary AUR malware scanner"

if command -v archcanary > /dev/null 2>&1; then
    LogText "Result: archcanary found at $(command -v archcanary)"
    Display --indent 2 --text "- Archcanary AUR scanner" --result FOUND --color GREEN
    AddHP 3 3
else
    LogText "Result: archcanary not found"
    Display --indent 2 --text "- Archcanary AUR scanner" --result "NOT FOUND" --color YELLOW
    ReportSuggestion "ARCH-0001" "Install archcanary to detect compromised AUR packages" \
        "https://github.com/musqz/archcanary" "-"
    AddHP 0 3
fi
