#!/usr/bin/env bash
# Demo: alle aur_check_py CLI-Fälle aus dem README
set -euo pipefail
cd "$(dirname "$0")"/..

P="python -m aur_check_py"
SEP="========================================"

echo "$SEP"
echo " 1) --help"
echo "$SEP"
$P --help || true
echo

echo "$SEP"
echo " 2) Standard-Scan (v2-Äquivalent)"
echo "    python -m aur_check_py"
echo "$SEP"
$P || true
echo

echo "$SEP"
echo " 3) --all-time (kein Datumsfenster)"
echo "$SEP"
$P --all-time || true
echo

echo "$SEP"
echo " 4) --full (alle Checks)"
echo "$SEP"
$P --full || true
echo

echo "$SEP"
echo " 5) Einzel-Checks"
echo "$SEP"
$P --check-systemd || true
echo "---"
$P --check-ebpf || true
echo "---"
$P --check-npm-cache || true
echo "---"
$P --check-bun-cache || true
echo

echo "$SEP"
echo " 6) Merge-Mode: HedgeDoc + lokale package_list.txt"
echo "    python -m aur_check_py --merge -l ../package_list.txt"
echo "$SEP"
$P --merge -l ../package_list.txt || true
echo

echo "$SEP"
echo " 7) Merge-Mode: --skip-hedgedoc + --all-time"
echo "$SEP"
$P --merge --skip-hedgedoc -l ../package_list.txt --all-time || true
echo

echo "$SEP"
echo " 8) --verbose output"
echo "$SEP"
$P --verbose || true
echo

echo "$SEP"
echo " 9) Custom package/npm lists"
echo "$SEP"
$P --package-list=../package_list.txt --malicious-npm-list=../malicious_npm_packages.txt || true
echo

echo "$SEP"
echo " 10) --refresh (HedgeDoc live fetch)"
echo "$SEP"
$P --refresh --verbose || true
echo

echo "$SEP"
echo " ALL CASES DONE"
echo "$SEP"
