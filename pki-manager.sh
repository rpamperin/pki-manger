#!/usr/bin/env bash
# pki-manager.sh - TUI for the pamperins.lan internal PKI.
# Also the non-interactive entry point used by pki-web.py.
set -uo pipefail

SELF_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
. "$SELF_DIR/lib/pki-lib.sh"

usage() {
    cat <<EOF
usage: pki-manager.sh [--conf FILE] [MODE]

modes:
  (none)                  interactive dashboard + menu
  --status                print the dashboard and exit
  --status-json           print status as JSON
  --status-records        print status as TSV records (section/id/state/label/detail)
  --run ACTION [ARG]      run one action non-interactively
  --list-actions          list valid action names
  --list-hosts            list configured hosts
  --dump-config           print the settings pki-web.py needs (KEY=VALUE)
  -h, --help              this

actions: $(printf '%s' "$PKI_ACTIONS" | tr '\n' ' ')
EOF
}

# --------------------------------------------------------------- argv ------
MODE=interactive ACTION="" ARG=""
while [ $# -gt 0 ]; do
    case "$1" in
        --conf)           PKI_CONF="$2"; shift 2 ;;
        --status)         MODE=status; shift ;;
        --status-json)    MODE=json; shift ;;
        --status-records) MODE=records; shift ;;
        --list-actions)   MODE=list-actions; shift ;;
        --list-hosts)     MODE=list-hosts; shift ;;
        --dump-config)    MODE=dump-config; shift ;;
        --run)            MODE=run; ACTION="${2:-}"; ARG="${3:-}"; shift; shift || true; shift || true ;;
        -h|--help)        usage; exit 0 ;;
        *)                pki_err "unknown option: $1"; usage >&2; exit 2 ;;
    esac
done

pki_load_conf

case "$MODE" in
    status)       pki_collect_status | pki_render_text; exit 0 ;;
    json)         pki_collect_status | pki_render_json; exit 0 ;;
    records)      pki_collect_status; exit 0 ;;
    list-actions) printf '%s\n' $PKI_ACTIONS; exit 0 ;;
    dump-config)  for k in PKI_CONF PKI_ROOT DOMAIN HOSTS LOG_DIR YUBIKEY_SLOT \
                           ROOT_CA_CRT INT_CA_CRT RENEW_SCRIPT PKI_TTY_ACTIONS \
                           WEB_BIND WEB_PORT WEB_TOKEN WEB_TLS_CERT WEB_TLS_KEY; do
                      printf '%s=%s\n' "$k" "$(printf '%s' "${!k}" | tr '\n' ' ')"
                  done; exit 0 ;;
    list-hosts)   for h in $HOSTS; do printf '%s\t%s\t%s\n' "$h" "$(pki_host_addr "$h")" "$(pki_host_roles "$h")"; done; exit 0 ;;
    run)          [ -n "$ACTION" ] || { pki_err "--run needs an action"; exit 2; }
                  pki_run_action "$ACTION" "$ARG"; exit $? ;;
esac

# ---------------------------------------------------------- interactive ----

STATUS_CACHE=""

refresh_status() {
    printf '%sscanning...%s\r' "$C_DIM" "$C_RESET"
    STATUS_CACHE="$(pki_collect_status)"
    printf '            \r'
}

banner() {
    local overall
    overall=$(printf '%s\n' "$STATUS_CACHE" | cut -f3 | { w=ok; while read -r s; do w=$(pki_worst "$w" "$s"); done; printf '%s' "$w"; })
    clear
    printf '%s+----------------------------------------------------------------------------+%s\n' "$C_INFO" "$C_RESET"
    printf '%s| PAMPERINS LAN - PKI MANAGER%-30s%s%-19s%s|%s\n' \
        "$C_INFO" "" "$(pki_state_color "$overall")" "$(date '+%Y-%m-%d %H:%M:%S')" "$C_INFO" "$C_RESET"
    printf '%s+----------------------------------------------------------------------------+%s\n\n' "$C_INFO" "$C_RESET"
}

menu() {
    cat <<EOF
${C_HEAD}ACTIONS${C_RESET}
   1  Renew certificates              7  LDAP trust fix (ldap.conf)
   2  Deploy certs to a host          8  Nextcloud cert check
   3  Deploy certs to ALL hosts       9  Verify TLS endpoints
   4  Push root CA trust             10  View logs
   5  Push Webmin cert (leaf+int)    11  Samba TLS ownership fix
   6  Fix Webmin miniserv.conf        y  YubiKey management
                                      r  Refresh      q  Quit
EOF
}

yk_menu() {
    cat <<EOF

${C_HEAD}YUBIKEY${C_RESET}  root CA key, slot ${YUBIKEY_SLOT}
   1  Key info / PIV status           6  Sign intermediate CSR   ${C_WARN}(PIN+touch)${C_RESET}
   2  Slot certificate detail         7  Change PIN              ${C_WARN}(PIN)${C_RESET}
   3  Export root CA cert to disk     8  Change PUK              ${C_WARN}(PUK)${C_RESET}
   4  PIN / PUK retry counters        9  Unblock PIN with PUK    ${C_WARN}(PUK)${C_RESET}
   5  Test-sign ${C_WARN}(PIN+touch)${C_RESET}          10  Change management key   ${C_WARN}(mgmt key)${C_RESET}
   c  back
EOF
    printf '%syubikey>%s ' "$C_BOLD" "$C_RESET"
    local y; read -r y || return 0
    printf '\n'
    case "$y" in
        1)  pki_run_action yk-info ;;
        2)  pki_run_action yk-slot "$YUBIKEY_SLOT" ;;
        3)  confirm "Overwrite $ROOT_CA_CRT from slot $YUBIKEY_SLOT?" && pki_run_action yk-export-cert "$YUBIKEY_SLOT" ;;
        4)  pki_run_action yk-retries ;;
        5)  pki_run_action yk-test "$YUBIKEY_SLOT" ;;
        6)  printf 'CSR path [%s]> ' "$INT_CA_DIR/$INT_CA_NAME.csr"
            local csr; read -r csr || true
            confirm "Sign ${csr:-$INT_CA_DIR/$INT_CA_NAME.csr} with the offline root key?" \
                && pki_run_action yk-sign-intermediate "${csr:-$INT_CA_DIR/$INT_CA_NAME.csr}" ;;
        7)  pki_run_action yk-change-pin ;;
        8)  pki_run_action yk-change-puk ;;
        9)  pki_run_action yk-unblock-pin ;;
        10) confirm "Change the management key? A lost mgmt key cannot be recovered." \
                && pki_run_action yk-change-mgmt ;;
        c|C|'') return 0 ;;
        *)  pki_err "no such option: $y" ;;
    esac
}

pause() { printf '\n%s-- enter to continue --%s' "$C_DIM" "$C_RESET"; read -r _ || true; }

pick_host() {  # echoes a host name on stdout, or nothing if cancelled
    local i=1 h list=()
    for h in $HOSTS; do list+=("$h"); done
    {
        printf '\n'
        for h in "${list[@]}"; do
            printf '   %d  %-10s %-10s %s\n' "$i" "$h" "$(pki_host_addr "$h")" "$(pki_host_roles "$h")"
            i=$((i+1))
        done
        printf '   a  all\n   c  cancel\n'
        printf 'host> '
    } >&2
    local sel; read -r sel || return 1
    case "$sel" in
        a|A) printf 'ALL'; return 0 ;;
        c|C|'') return 1 ;;
        *[!0-9]*|'') return 1 ;;
    esac
    [ "$sel" -ge 1 ] && [ "$sel" -le "${#list[@]}" ] || return 1
    printf '%s' "${list[$((sel-1))]}"
}

# run <action-for-one-host> honouring the "all" selection
run_hostwise() {
    local base="$1" sel
    sel=$(pick_host) || { pki_info "cancelled"; return 0; }
    printf '\n'
    if [ "$sel" = ALL ]; then
        pki_run_action "$base-all"
    else
        pki_run_action "$base" "$sel"
    fi
}

confirm() {
    local ans
    printf '%s%s%s [y/N] ' "$C_WARN" "$1" "$C_RESET"
    read -r ans || return 1
    case "$ans" in y|Y|yes|YES) return 0 ;; *) pki_info "cancelled"; return 1 ;; esac
}

refresh_status
while true; do
    banner
    printf '%s\n' "$STATUS_CACHE" | pki_render_text
    menu
    printf '\n%sselect>%s ' "$C_BOLD" "$C_RESET"
    read -r choice || break
    printf '\n'
    case "$choice" in
        1)  confirm "Run $RENEW_SCRIPT?" && pki_run_action renew ;;
        2)  run_hostwise deploy ;;
        3)  confirm "Deploy certs to ALL hosts ($HOSTS)?" && pki_run_action deploy-all ;;
        4)  run_hostwise trust-push ;;
        5)  run_hostwise webmin-push ;;
        6)  run_hostwise webmin-fix ;;
        7)  run_hostwise ldap-fix ;;
        8)  printf '   1  auto (decide from live trust test)\n   2  enforce cert checking\n   3  bypass cert checking\nmode> '
            read -r m || true
            case "$m" in
                1) pki_run_action nextcloud-certcheck auto ;;
                2) pki_run_action nextcloud-certcheck enforce ;;
                3) pki_run_action nextcloud-certcheck bypass ;;
                *) pki_info "cancelled" ;;
            esac ;;
        9)  sel=$(pick_host) || sel=""
            [ "$sel" = ALL ] && sel=""
            printf '\n'; pki_run_action verify-tls "$sel" ;;
        10) printf 'lines [60]> '; read -r n || true; pki_run_action logs "${n:-60}" ;;
        11) run_hostwise samba-fix ;;
        y|Y) yk_menu ;;
        r|R|'') ;;
        q|Q) clear; exit 0 ;;
        *)  pki_err "no such option: $choice" ;;
    esac
    [ "$choice" = r ] || [ "$choice" = R ] || [ -z "$choice" ] || pause
    refresh_status          # auto-refresh after every action
done
