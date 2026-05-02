#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Daily Security Tools — quick runner
# Usage:
#   bash run.sh <keyword> [args passed to the tool]
#
# Examples:
#   bash run.sh jenkins --target https://jenkins.example.com
#   bash run.sh ssrf --list targets.txt --output findings.json
#   bash run.sh CVE-2025-43268 --target https://argocd.example.com --safe
#
# One-liner (no clone needed):
#   bash <(curl -fsSL https://raw.githubusercontent.com/thecosmicexplorer/tools/main/run.sh) jenkins
# ─────────────────────────────────────────────────────────────

set -euo pipefail

REPO="https://raw.githubusercontent.com/thecosmicexplorer/tools/main"
BOLD="\033[1m"; RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; CYAN="\033[36m"; RESET="\033[0m"

die()  { echo -e "${RED}[!] $*${RESET}" >&2; exit 1; }
info() { echo -e "${CYAN}[*] $*${RESET}"; }
ok()   { echo -e "${GREEN}[+] $*${RESET}"; }

[[ $# -lt 1 ]] && { echo -e "${BOLD}Usage:${RESET} bash run.sh <keyword> [tool args...]"; exit 1; }

KEYWORD="${1,,}"; shift
TOOL_ARGS=("$@")

# Fetch the index
info "Fetching tool index..."
INDEX_JSON=$(curl -fsSL "${REPO}/tools.json") || die "Could not fetch tools.json"

# Search by name, category, CVE, or target
MATCHES=$(echo "$INDEX_JSON" | python3 -c "
import json, sys
data = json.load(sys.stdin)
kw = '${KEYWORD}'.lower()
hits = []
for t in data:
    searchable = ' '.join([
        t.get('name',''), t.get('category',''),
        t.get('cve','') or '', t.get('description',''),
        ' '.join(t.get('targets',[]))
    ]).lower()
    if kw in searchable:
        hits.append(t)
for h in hits:
    cve = h.get('cve') or '—'
    print(f\"{h['path']}|{h['category']}|{cve}|{h['description'][:60]}\")
")

if [[ -z "$MATCHES" ]]; then
    die "No tools found matching '${KEYWORD}'. Try: jenkins, ssrf, CVE-2025-68613, keycloak…"
fi

MATCH_COUNT=$(echo "$MATCHES" | wc -l | tr -d ' ')

if [[ "$MATCH_COUNT" -eq 1 ]]; then
    SELECTED="$MATCHES"
else
    echo -e "\n${BOLD}Multiple matches for '${KEYWORD}':${RESET}"
    i=1
    while IFS='|' read -r path cat cve desc; do
        printf "  %s%d)%s %-55s %s%-20s%s %s\n" "$BOLD" $i "$RESET" "$path" "$CYAN" "$cve" "$RESET" "$desc"
        ((i++))
    done <<< "$MATCHES"
    echo ""
    read -rp "Pick a number [1-${MATCH_COUNT}]: " PICK
    [[ "$PICK" =~ ^[0-9]+$ && "$PICK" -ge 1 && "$PICK" -le "$MATCH_COUNT" ]] || die "Invalid choice"
    SELECTED=$(echo "$MATCHES" | sed -n "${PICK}p")
fi

TOOL_PATH=$(echo "$SELECTED" | cut -d'|' -f1)
TOOL_NAME=$(basename "$TOOL_PATH")

# Check for Python / pip
command -v python3 &>/dev/null || die "python3 is required"
python3 -c "import httpx" 2>/dev/null || {
    info "Installing httpx..."
    pip install httpx -q
}

# If we're in the repo already, run locally; otherwise download
if [[ -f "$TOOL_PATH" ]]; then
    info "Running ${TOOL_NAME} (local)..."
    python3 "$TOOL_PATH" "${TOOL_ARGS[@]}"
else
    TMP=$(mktemp /tmp/"${TOOL_NAME%.py}"_XXXXXX.py)
    info "Downloading ${TOOL_PATH}..."
    curl -fsSL "${REPO}/${TOOL_PATH}" -o "$TMP" || die "Download failed"
    ok "Running ${TOOL_NAME}..."
    python3 "$TMP" "${TOOL_ARGS[@]}"
    rm -f "$TMP"
fi
