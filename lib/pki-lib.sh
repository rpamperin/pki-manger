#!/usr/bin/env bash
# pki-lib.sh - shared logic for pki-manager.sh (TUI) and pki-web.py (Flask).
# Sourced, never executed directly. All credentials come from pki.conf.
# shellcheck shell=bash disable=SC1090,SC2034

[ -n "${_PKI_LIB_LOADED:-}" ] && return 0
_PKI_LIB_LOADED=1

PKI_LIB_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PKI_APP_DIR="$(cd -- "$PKI_LIB_DIR/.." && pwd)"

# ---------------------------------------------------------------- config ----

pki_load_conf() {
    local conf="${PKI_CONF:-$HOME/pki/pki.conf}"
    PKI_CONF_LOADED=0
    PKI_CONF_PERM=""
    if [ -r "$conf" ]; then
        . "$conf"
        PKI_CONF_LOADED=1
        PKI_CONF_PERM="$(stat -c '%a' "$conf" 2>/dev/null || echo '?')"
    fi
    PKI_CONF="$conf"
    pki_apply_defaults
}

pki_apply_defaults() {
    PKI_ROOT="${PKI_ROOT:-$HOME/pki}"
    DOMAIN="${DOMAIN:-pamperins.lan}"

    CERT_DIR="${CERT_DIR:-$PKI_ROOT/certs}"
    ROOT_CA_DIR="${ROOT_CA_DIR:-$PKI_ROOT/root-ca}"
    INT_CA_DIR="${INT_CA_DIR:-$PKI_ROOT/intermediate-ca}"
    LOG_DIR="${LOG_DIR:-$PKI_ROOT/logs}"

    ROOT_CA_NAME="${ROOT_CA_NAME:-pamperins-root-ca}"
    ROOT_CA_CRT="${ROOT_CA_CRT:-$ROOT_CA_DIR/$ROOT_CA_NAME.crt}"
    INT_CA_NAME="${INT_CA_NAME:-pamperins-intermediate-ca}"
    INT_CA_CRT="${INT_CA_CRT:-$INT_CA_DIR/$INT_CA_NAME.crt}"
    INT_CA_KEY="${INT_CA_KEY:-$INT_CA_DIR/$INT_CA_NAME.key}"
    # Stale anchor name that keeps reappearing in /etc/ldap/ldap.conf.
    STALE_CA_NAME="${STALE_CA_NAME:-pamperins-ca.crt}"

    if [ -z "${RENEW_SCRIPT:-}" ]; then
        if [ -x "$PKI_APP_DIR/renew-certs.sh" ]; then RENEW_SCRIPT="$PKI_APP_DIR/renew-certs.sh"
        else RENEW_SCRIPT="$PKI_ROOT/renew-certs.sh"; fi
    fi
    INIT_SCRIPT="${INIT_SCRIPT:-$PKI_APP_DIR/pki-init.sh}"
    MANAGER_LOG="${MANAGER_LOG:-$LOG_DIR/pki-manager.log}"

    WARN_DAYS="${WARN_DAYS:-30}"
    CRIT_DAYS="${CRIT_DAYS:-7}"

    SSH_USER="${SSH_USER:-root}"
    SSH_PORT="${SSH_PORT:-22}"
    SSH_KEY="${SSH_KEY:-}"
    SSH_PASS="${SSH_PASS:-}"
    SUDO_PASS="${SUDO_PASS:-}"
    NET_TIMEOUT="${NET_TIMEOUT:-5}"
    CMD_TIMEOUT="${CMD_TIMEOUT:-120}"

    WEBMIN_PORT="${WEBMIN_PORT:-10000}"
    WEBMIN_DIR="${WEBMIN_DIR:-/etc/webmin}"
    WEBMIN_CERT="${WEBMIN_CERT:-$WEBMIN_DIR/miniserv.cert}"
    WEBMIN_KEY="${WEBMIN_KEY:-$WEBMIN_DIR/miniserv.pem}"
    WEBMIN_CONF="${WEBMIN_CONF:-$WEBMIN_DIR/miniserv.conf}"
    WEBMIN_SERVICE="${WEBMIN_SERVICE:-webmin}"

    SAMBA_TLS_DIR="${SAMBA_TLS_DIR:-/var/lib/samba/private/tls}"
    SAMBA_SERVICE="${SAMBA_SERVICE:-samba-ad-dc}"
    LDAP_CONF="${LDAP_CONF:-/etc/ldap/ldap.conf}"
    TRUST_ANCHOR_DIR="${TRUST_ANCHOR_DIR:-/usr/local/share/ca-certificates}"

    NEXTCLOUD_DIR="${NEXTCLOUD_DIR:-/var/www/nextcloud}"
    NEXTCLOUD_USER="${NEXTCLOUD_USER:-www-data}"
    NEXTCLOUD_PHP="${NEXTCLOUD_PHP:-php}"
    NEXTCLOUD_PROBE_URL="${NEXTCLOUD_PROBE_URL:-}"

    # --- CA creation / issuance ---------------------------------------
    ROOT_CA_SUBJECT="${ROOT_CA_SUBJECT:-/O=pamperins.lan/CN=Pamperins Root CA}"
    INT_CA_SUBJECT="${INT_CA_SUBJECT:-/O=pamperins.lan/CN=Pamperins Intermediate CA}"
    ROOT_CA_DAYS="${ROOT_CA_DAYS:-7300}"
    LEAF_DAYS="${LEAF_DAYS:-397}"
    RENEW_BEFORE_DAYS="${RENEW_BEFORE_DAYS:-30}"
    KEY_ALGO="${KEY_ALGO:-rsa2048}"          # rsa2048 | rsa4096 | ecp256 | ecp384
    YK_KEY_ALGO="${YK_KEY_ALGO:-RSA2048}"    # what the YubiKey generates in slot 9c
    YK_PIN_POLICY="${YK_PIN_POLICY:-ONCE}"
    YK_TOUCH_POLICY="${YK_TOUCH_POLICY:-ALWAYS}"
    INT_CA_CSR="${INT_CA_CSR:-$INT_CA_DIR/$INT_CA_NAME.csr}"
    INT_CA_KEY_PASS="${INT_CA_KEY_PASS:-}"   # empty = unencrypted (needed for unattended renewal)
    CA_SERIAL="${CA_SERIAL:-$INT_CA_DIR/serial}"

    TECHNITIUM_SERVICE="${TECHNITIUM_SERVICE:-dns}"
    TECHNITIUM_USER="${TECHNITIUM_USER:-dns}"
    TECHNITIUM_PFX="${TECHNITIUM_PFX:-/etc/dns/ssl/pamperins.pfx}"
    TECHNITIUM_PFX_PASS="${TECHNITIUM_PFX_PASS:-}"

    APACHE_SERVICE="${APACHE_SERVICE:-apache2}"
    APACHE_CERT_DIR="${APACHE_CERT_DIR:-/etc/ssl/pamperins}"

    WEB_BIND="${WEB_BIND:-127.0.0.1}"
    WEB_PORT="${WEB_PORT:-7443}"
    WEB_TOKEN="${WEB_TOKEN:-}"
    WEB_TLS_CERT="${WEB_TLS_CERT:-}"
    WEB_TLS_KEY="${WEB_TLS_KEY:-}"

    YUBIKEY_SLOT="${YUBIKEY_SLOT:-9c}"
    # PIV slot 9c == PKCS#11 id 02, label "SIGN key". The PIN is never stored here.
    PKCS11_MODULE="${PKCS11_MODULE:-/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so}"
    YK_ROOT_KEY_URI="${YK_ROOT_KEY_URI:-pkcs11:object=SIGN%20key;type=private}"
    INT_CA_DAYS="${INT_CA_DAYS:-1825}"

    HOSTS="${HOSTS:-dc gateway ns1}"
    HOST_dc_ADDR="${HOST_dc_ADDR:-${DC_HOST:-10.0.2.2}}"
    HOST_gateway_ADDR="${HOST_gateway_ADDR:-${GATEWAY_HOST:-10.0.2.3}}"
    HOST_ns1_ADDR="${HOST_ns1_ADDR:-${NS1_HOST:-10.0.2.4}}"
    HOST_dc_ROLES="${HOST_dc_ROLES:-samba ldaps webmin nextcloud}"
    HOST_gateway_ROLES="${HOST_gateway_ROLES:-apache webmin}"
    HOST_ns1_ROLES="${HOST_ns1_ROLES:-dns webmin}"
}

pki_hosts()      { printf '%s\n' $HOSTS; }
pki_host_valid() { case " $HOSTS " in *" $1 "*) return 0 ;; esac; return 1; }
pki_host_addr()  { local v="HOST_${1}_ADDR";  printf '%s' "${!v:-$1}"; }
pki_host_fqdn()  { local v="HOST_${1}_FQDN";  printf '%s' "${!v:-$1.$DOMAIN}"; }
pki_host_roles() { local v="HOST_${1}_ROLES"; printf '%s' "${!v:-}"; }
pki_host_has_role() { case " $(pki_host_roles "$1") " in *" $2 "*) return 0 ;; esac; return 1; }
pki_host_cert()  { local v="HOST_${1}_CERT"; printf '%s' "${!v:-$CERT_DIR/$(pki_host_fqdn "$1").crt}"; }
pki_host_key()   { local v="HOST_${1}_KEY";  printf '%s' "${!v:-$CERT_DIR/$(pki_host_fqdn "$1").key}"; }

# ----------------------------------------------------------------- utils ----

C_RESET=''; C_BOLD=''; C_DIM=''
C_OK=''; C_WARN=''; C_ERR=''; C_INFO=''; C_HEAD=''
pki_colors_on() {
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
    C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'
    C_INFO=$'\033[36m'; C_HEAD=$'\033[1;37m'
}
[ -t 1 ] && [ "${NO_COLOR:-}" = "" ] && pki_colors_on

pki_err()  { printf '%sERR%s  %s\n' "$C_ERR" "$C_RESET" "$*" >&2; }
pki_warn() { printf '%sWARN%s %s\n' "$C_WARN" "$C_RESET" "$*" >&2; }
pki_ok()   { printf '%sOK%s   %s\n' "$C_OK" "$C_RESET" "$*"; }
pki_info() { printf '%s\n' "$*"; }

pki_log() {
    [ -d "$LOG_DIR" ] || mkdir -p "$LOG_DIR" 2>/dev/null || return 0
    printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >>"$MANAGER_LOG" 2>/dev/null || true
}

pki_need() {
    command -v "$1" >/dev/null 2>&1 && return 0
    pki_err "missing tool: $1${2:+ ($2)}"
    return 1
}

# worst state of the arguments given
pki_worst() {
    local worst=ok s
    for s in "$@"; do
        case "$s" in
            err)  worst=err ;;
            warn) [ "$worst" = err ] || worst=warn ;;
            unknown) [ "$worst" = ok ] && worst=unknown ;;
        esac
    done
    printf '%s' "$worst"
}

# PIN/touch operations need a real terminal: ykman prompts, and we will not
# accept a PIV PIN through the web UI.
pki_tty_required() {
    if [ "${PKI_NONINTERACTIVE:-0}" = 1 ] || [ ! -t 0 ]; then
        pki_err "$1 requires a terminal (PIN/touch entry) - run it from the TUI on the console"
        return 1
    fi
    return 0
}

pki_tcp() {  # host port [timeout]
    local h="$1" p="$2" t="${3:-$NET_TIMEOUT}"
    timeout "$t" bash -c "exec 3<>/dev/tcp/$h/$p" 2>/dev/null
}

# ------------------------------------------------------------------ ssh -----

pki_ssh_base() {
    local h="$1"
    local common=(-o StrictHostKeyChecking=accept-new
                  -o ConnectTimeout="$NET_TIMEOUT" -o LogLevel=ERROR)
    [ -n "$SSH_KEY" ] && common+=(-i "$SSH_KEY" -o IdentitiesOnly=yes)
    if [ -n "$SSH_PASS" ] && command -v sshpass >/dev/null 2>&1; then
        common+=(-o BatchMode=no -o PubkeyAuthentication=no)
        SSH_WRAP=(sshpass -e)
    else
        common+=(-o BatchMode=yes)
        SSH_WRAP=()
    fi
    SSH_ARGS=("${common[@]}" -p "$SSH_PORT")   # ssh uses -p
    SCP_ARGS=("${common[@]}" -P "$SSH_PORT")   # scp uses -P
    SSH_TARGET="$SSH_USER@$(pki_host_addr "$h")"
}

# pki_ssh <host> <command...>  - run remotely, stdout/stderr passed through
pki_ssh() {
    local h="$1"; shift
    pki_ssh_base "$h"
    SSHPASS="$SSH_PASS" timeout "$CMD_TIMEOUT" \
        "${SSH_WRAP[@]}" ssh "${SSH_ARGS[@]}" "$SSH_TARGET" "$@"
}

# pki_ssh_sudo <host> <shell-snippet> - run snippet as root on the remote
pki_ssh_sudo() {
    local h="$1" snippet="$2"
    if [ "$SSH_USER" = root ]; then
        pki_ssh "$h" "$snippet"
    elif [ -n "$SUDO_PASS" ]; then
        pki_ssh "$h" "sudo -S -p '' bash -c $(pki_shq "$snippet")" <<<"$SUDO_PASS"
    else
        pki_ssh "$h" "sudo -n bash -c $(pki_shq "$snippet")"
    fi
}

# pki_scp_raw <host> <local> <remote> - upload only, no privilege step
pki_scp_raw() {
    pki_ssh_base "$1"
    SSHPASS="$SSH_PASS" timeout "$CMD_TIMEOUT" \
        "${SSH_WRAP[@]}" scp "${SCP_ARGS[@]}" "$2" "$SSH_TARGET:$3" >/dev/null
}

# pki_scp_to <host> <local> <remote-path> [mode] - stage, then install as root
pki_scp_to() {
    local h="$1" src="$2" dst="$3" mode="${4:-0644}"
    local stage="/tmp/.pki-push.$$.$(basename "$dst")"
    pki_ssh_base "$h"
    if ! SSHPASS="$SSH_PASS" timeout "$CMD_TIMEOUT" \
         "${SSH_WRAP[@]}" scp "${SCP_ARGS[@]}" "$src" "$SSH_TARGET:$stage" >/dev/null; then
        pki_err "scp $(basename "$src") -> $h failed"
        return 1
    fi
    pki_ssh_sudo "$h" "install -o root -g root -m $mode $(pki_shq "$stage") $(pki_shq "$dst"); rc=\$?; rm -f $(pki_shq "$stage"); exit \$rc"
}

pki_shq() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

# ------------------------------------------------------------ tls probes ----

# pki_tls_fetch <addr> <port> <sni> <outfile>
pki_tls_fetch() {
    local a="$1" p="$2" sni="$3" out="$4"
    local ca=()
    [ -r "$ROOT_CA_CRT" ] && ca=(-CAfile "$ROOT_CA_CRT")
    timeout "$NET_TIMEOUT" openssl s_client -connect "$a:$p" -servername "$sni" \
        -showcerts "${ca[@]}" </dev/null >"$out" 2>&1
    [ -s "$out" ]
}

pki_tls_chain_len()  { local n; n=$(grep -c 'BEGIN CERTIFICATE' "$1" 2>/dev/null); printf '%s' "${n:-0}"; }
pki_tls_verify_ok()  { grep -q 'Verify return code: 0 (ok)' "$1" 2>/dev/null; }
pki_tls_verify_msg() { sed -n 's/^ *Verify return code: //p' "$1" 2>/dev/null | tail -1; }
pki_tls_subject()    { sed -n 's/^subject=//p' "$1" 2>/dev/null | head -1; }
pki_tls_issuer()     { sed -n 's/^issuer=//p' "$1" 2>/dev/null | head -1; }

pki_tls_days() {  # days left on the leaf cert in an s_client dump
    local end
    end=$(openssl x509 -enddate -noout <"$1" 2>/dev/null) || return 1
    pki_days_until "${end#notAfter=}"
}

pki_days_until() {
    local ts now
    ts=$(date -d "$1" +%s 2>/dev/null) || return 1
    now=$(date +%s)
    printf '%s' $(( (ts - now) / 86400 ))
}

pki_cert_days() {  # days left on a local cert file
    local end
    end=$(openssl x509 -enddate -noout -in "$1" 2>/dev/null) || return 1
    pki_days_until "${end#notAfter=}"
}

pki_cert_subject() {
    openssl x509 -noout -subject -in "$1" 2>/dev/null | sed 's/^subject=*//'
}

pki_days_state() {
    local d="$1"
    case "$d" in ''|*[!0-9-]*) printf 'unknown'; return ;; esac
    if   [ "$d" -le "$CRIT_DAYS" ]; then printf 'err'
    elif [ "$d" -le "$WARN_DAYS" ]; then printf 'warn'
    else printf 'ok'
    fi
}

# --------------------------------------------------------------- records ----
# Every probe emits: section \t id \t state \t label \t detail

pki_rec() { printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5"; }

pki_probe_conf() {
    if [ "$PKI_CONF_LOADED" = 1 ]; then
        case "$PKI_CONF_PERM" in
            600|400) pki_rec conf pki.conf ok "loaded" "$PKI_CONF (mode $PKI_CONF_PERM)" ;;
            *) pki_rec conf pki.conf warn "mode $PKI_CONF_PERM" "$PKI_CONF should be chmod 600" ;;
        esac
    else
        pki_rec conf pki.conf err "missing" "$PKI_CONF not readable - using defaults"
    fi
}

pki_probe_yubikey() {
    if ! command -v ykman >/dev/null 2>&1; then
        pki_rec yubikey yubikey unknown "ykman missing" "install yubikey-manager to manage slot $YUBIKEY_SLOT"
        return
    fi
    local out serial tries algo expires days st
    if ! out=$(timeout 15 ykman piv info 2>&1); then
        pki_rec yubikey yubikey err "not present" "$(printf '%s' "$out" | head -1)"
        return
    fi
    serial=$(timeout 10 ykman list --serials 2>/dev/null | head -1)
    tries=$(printf '%s' "$out" | sed -n 's/.*PIN tries remaining: *//p' | head -1)

    if pki_yk_slot_occupied "$YUBIKEY_SLOT"; then
        algo=$(printf '%s' "$out" | sed -n "/^[Ss]lot ${YUBIKEY_SLOT}/I,/^[Ss]lot /Ip" \
               | sed -n 's/.*[Pp]rivate key type: *//p' | head -1)
        # Firmware below 5.3 has no PIV key metadata, so ykman prints EMPTY
        # when it cannot read the algorithm. That means "unknown", not "no
        # key" - reporting it verbatim looks like the slot was wiped.
        case "$algo" in
            EMPTY|empty|''|*[Uu]nknown*) algo="algorithm not reported by this firmware" ;;
        esac
        pki_rec yubikey slot-$YUBIKEY_SLOT ok "key present" "serial ${serial:-?}, $algo, PIN tries ${tries:-?}"
    else
        pki_rec yubikey slot-$YUBIKEY_SLOT err "slot empty" "no root CA key on serial ${serial:-?}"
    fi

    # PIN lockout is the thing that silently ends your ability to sign
    case "${tries%%/*}" in
        ''|*[!0-9]*) ;;
        0) pki_rec yubikey pin err "BLOCKED" "PIN locked - unblock with the PUK (yk-unblock-pin)" ;;
        1|2) pki_rec yubikey pin warn "$tries tries left" "verify the PIN to reset the counter" ;;
        *) pki_rec yubikey pin ok "$tries tries left" "" ;;
    esac

    # expiry of the CA cert actually stored on the key
    local tmp fp_slot fp_disk; tmp=$(mktemp)
    if pki_yk_export_cert "$YUBIKEY_SLOT" "$tmp" 2>/dev/null && [ -s "$tmp" ]; then
        days=$(pki_cert_days "$tmp")
        st=$(pki_days_state "$days")
        if ! pki_cert_is_ca "$tmp"; then
            pki_rec yubikey slot-cert err "not a CA" \
                "slot holds a non-CA cert - finish: ./pki-init.sh --reuse-slot"
        elif [ -r "$ROOT_CA_CRT" ]; then
            fp_slot=$(openssl x509 -in "$tmp" -noout -fingerprint -sha256 2>/dev/null)
            fp_disk=$(openssl x509 -in "$ROOT_CA_CRT" -noout -fingerprint -sha256 2>/dev/null)
            if [ "$fp_slot" = "$fp_disk" ]; then
                pki_rec yubikey slot-cert "$st" "${days:-?}d" "$(pki_cert_subject "$tmp")"
            else
                pki_rec yubikey slot-cert warn "stale (${days:-?}d)" \
                    "differs from $ROOT_CA_CRT - the import never finished"
            fi
        else
            pki_rec yubikey slot-cert "$st" "${days:-?}d" "$(pki_cert_subject "$tmp")"
        fi
    fi
    rm -f "$tmp"
}

pki_probe_certs() {
    local f name days st
    for f in "$ROOT_CA_CRT" "$INT_CA_CRT"; do
        [ -n "$f" ] || continue
        name=$(basename "$f"); name="${name%.*}"
        if [ ! -r "$f" ]; then
            pki_rec cert "$name" err "missing" "$f"
            continue
        fi
        days=$(pki_cert_days "$f") || { pki_rec cert "$name" err "unreadable" "$f"; continue; }
        st=$(pki_days_state "$days")
        pki_rec cert "$name" "$st" "${days}d" "$f"
    done
    if [ -d "$CERT_DIR" ]; then
        for f in "$CERT_DIR"/*.crt "$CERT_DIR"/*.pem; do
            [ -r "$f" ] || continue
            name=$(basename "$f"); name="${name%.*}"
            days=$(pki_cert_days "$f") || { pki_rec cert "$name" err "unreadable" "$f"; continue; }
            st=$(pki_days_state "$days")
            pki_rec cert "$name" "$st" "${days}d" "$(pki_cert_subject "$f")"
        done
    else
        pki_rec cert certs err "no cert dir" "$CERT_DIR"
    fi
}

pki_role_ports() {
    local h="$1" ports=""
    pki_host_has_role "$h" webmin    && ports="$ports $WEBMIN_PORT"
    pki_host_has_role "$h" apache    && ports="$ports 443"
    pki_host_has_role "$h" nextcloud && ports="$ports 443"
    pki_host_has_role "$h" ldaps     && ports="$ports 636"
    pki_host_has_role "$h" dns       && ports="$ports 53"
    printf '%s' "${ports# }"
}

pki_probe_servers() {
    local h addr up=0 down=0 detail="" p
    for h in $HOSTS; do
        addr=$(pki_host_addr "$h"); up=0; down=0; detail=""
        for p in $SSH_PORT $(pki_role_ports "$h"); do
            if pki_tcp "$addr" "$p" 3; then
                up=$((up+1)); detail="$detail ${p}:up"
            else
                down=$((down+1)); detail="$detail ${p}:down"
            fi
        done
        if   [ "$up" = 0 ];   then pki_rec server "$h" err  "unreachable" "$addr -$detail"
        elif [ "$down" = 0 ]; then pki_rec server "$h" ok   "up"          "$addr -$detail"
        else                       pki_rec server "$h" warn "degraded"    "$addr -$detail"
        fi
    done
}

pki_probe_ldaps() {
    local h addr fqdn tmp len days
    for h in $HOSTS; do
        pki_host_has_role "$h" ldaps || continue
        addr=$(pki_host_addr "$h"); fqdn=$(pki_host_fqdn "$h")
        tmp=$(mktemp)
        if ! pki_tls_fetch "$addr" 636 "$fqdn" "$tmp"; then
            pki_rec ldaps "$h" err "no answer" "ldaps://$addr:636"
            rm -f "$tmp"; continue
        fi
        len=$(pki_tls_chain_len "$tmp")
        days=$(pki_tls_days "$tmp")
        if pki_tls_verify_ok "$tmp"; then
            pki_rec ldaps "$h" ok "verified" "chain $len, ${days:-?}d left, $(pki_tls_issuer "$tmp")"
        else
            pki_rec ldaps "$h" err "verify failed" "$(pki_tls_verify_msg "$tmp") (chain $len)"
        fi
        rm -f "$tmp"
    done
}

pki_probe_webmin() {
    local h addr fqdn tmp len days
    for h in $HOSTS; do
        pki_host_has_role "$h" webmin || continue
        addr=$(pki_host_addr "$h"); fqdn=$(pki_host_fqdn "$h")
        tmp=$(mktemp)
        if ! pki_tls_fetch "$addr" "$WEBMIN_PORT" "$fqdn" "$tmp"; then
            pki_rec webmin "$h" err "no answer" "https://$addr:$WEBMIN_PORT"
            rm -f "$tmp"; continue
        fi
        len=$(pki_tls_chain_len "$tmp")
        days=$(pki_tls_days "$tmp")
        if [ "$len" -ge 2 ] && pki_tls_verify_ok "$tmp"; then
            pki_rec webmin "$h" ok "chain $len" "verified, ${days:-?}d left"
        elif [ "$len" -ge 2 ]; then
            pki_rec webmin "$h" warn "chain $len" "$(pki_tls_verify_msg "$tmp")"
        elif [ "$len" = 1 ]; then
            pki_rec webmin "$h" warn "chain 1" "leaf only - intermediate not bundled in miniserv.cert"
        else
            pki_rec webmin "$h" err "chain 0" "no certificate presented"
        fi
        rm -f "$tmp"
    done
}

# ------------------------------------------------------------- nextcloud ----

pki_nc_host() {  # first host carrying the nextcloud role
    local h
    for h in $HOSTS; do pki_host_has_role "$h" nextcloud && { printf '%s' "$h"; return 0; }; done
    return 1
}

pki_nc_probe_url() {
    [ -n "$NEXTCLOUD_PROBE_URL" ] && { printf '%s' "$NEXTCLOUD_PROBE_URL"; return; }
    local h
    for h in $HOSTS; do
        pki_host_has_role "$h" apache && { printf 'https://%s/' "$(pki_host_fqdn "$h")"; return; }
    done
    printf 'https://%s/' "$(pki_host_fqdn "$(pki_nc_host)")"
}

pki_nc_occ() {  # host args... - run occ as the web user
    local h="$1"; shift
    pki_ssh_sudo "$h" "cd $(pki_shq "$NEXTCLOUD_DIR") && sudo -u $(pki_shq "$NEXTCLOUD_USER") $(pki_shq "$NEXTCLOUD_PHP") occ $*"
}

# 0 = the host validates our chain with the system trust store
pki_nc_trust_ok() {
    local h="$1" url; url="$(pki_nc_probe_url)"
    pki_ssh "$h" "curl -sS --max-time 8 -o /dev/null $(pki_shq "$url")" >/dev/null 2>&1
}

pki_nc_certcheck_get() {  # echoes on|off|unknown
    local h="$1" v
    v=$(pki_nc_occ "$h" "config:system:get turnOffCertCheck" 2>/dev/null | tr -d '[:space:]')
    case "$v" in
        1|true)  printf 'on' ;;
        0|false) printf 'off' ;;
        '')      printf 'off' ;;   # unset == cert checking enabled
        *)       printf 'unknown' ;;
    esac
}

pki_probe_nextcloud() {
    local h cur trust
    h=$(pki_nc_host) || return 0
    if ! command -v ssh >/dev/null 2>&1; then
        pki_rec nextcloud "$h" unknown "ssh missing" "cannot query $NEXTCLOUD_DIR"
        return
    fi
    if ! pki_tcp "$(pki_host_addr "$h")" "$SSH_PORT" 3; then
        pki_rec nextcloud "$h" err "unreachable" "ssh $(pki_host_addr "$h"):$SSH_PORT closed"
        return
    fi
    cur=$(pki_nc_certcheck_get "$h")
    if pki_nc_trust_ok "$h"; then trust=ok; else trust=bad; fi
    if [ "$cur" = unknown ]; then
        pki_rec nextcloud "$h" err "occ failed" "cannot read turnOffCertCheck"
    elif [ "$trust" = ok ] && [ "$cur" = off ]; then
        pki_rec nextcloud "$h" ok "certcheck on" "trust verified, turnOffCertCheck=false"
    elif [ "$trust" = ok ] && [ "$cur" = on ]; then
        pki_rec nextcloud "$h" warn "certcheck off" "trust works - turnOffCertCheck can be cleared"
    elif [ "$trust" = bad ] && [ "$cur" = on ]; then
        pki_rec nextcloud "$h" warn "certcheck off" "workaround active - trust to $(pki_nc_probe_url) is broken"
    else
        pki_rec nextcloud "$h" err "certcheck on" "trust broken and no workaround - Nextcloud requests will fail"
    fi
}

# ---------------------------------------------------------- status/render ---

PKI_SECTIONS="conf yubikey cert server ldaps webmin nextcloud"

pki_collect_status() {
    pki_probe_conf
    pki_probe_yubikey
    pki_probe_certs
    pki_probe_servers
    pki_probe_ldaps
    pki_probe_webmin
    pki_probe_nextcloud
}

pki_state_color() {
    case "$1" in
        ok)   printf '%s' "$C_OK" ;;
        warn) printf '%s' "$C_WARN" ;;
        err)  printf '%s' "$C_ERR" ;;
        *)    printf '%s' "$C_DIM" ;;
    esac
}

pki_state_mark() {
    case "$1" in
        ok) printf ' OK ' ;; warn) printf 'WARN' ;; err) printf 'FAIL' ;; *) printf ' ?? ' ;;
    esac
}

pki_section_title() {
    case "$1" in
        conf) printf 'CONFIG' ;; yubikey) printf 'YUBIKEY' ;; cert) printf 'CERTIFICATES' ;;
        server) printf 'SERVERS' ;; ldaps) printf 'LDAPS' ;; webmin) printf 'WEBMIN CHAIN' ;;
        nextcloud) printf 'NEXTCLOUD' ;; *) printf '%s' "$1" ;;
    esac
}

# renders TSV records (stdin) as the colour dashboard
pki_render_text() {
    local recs sec s id st label detail c
    recs=$(cat)
    [ -n "$recs" ] || { printf '%sno status records%s\n' "$C_ERR" "$C_RESET"; return; }
    for sec in $PKI_SECTIONS; do
        # printf '%s\n' keeps the final record: `read` drops a line with no trailing newline
        printf '%s\n' "$recs" | grep -q "^$sec$(printf '\t')" || continue
        printf '%s%s%s\n' "$C_HEAD" "$(pki_section_title "$sec")" "$C_RESET"
        printf '%s\n' "$recs" | while IFS=$'\t' read -r s id st label detail; do
            [ "$s" = "$sec" ] || continue
            c=$(pki_state_color "$st")
            printf '  %s[%s]%s %-26s %-22s %s%s%s\n' \
                "$c" "$(pki_state_mark "$st")" "$C_RESET" "$id" "$label" "$C_DIM" "$detail" "$C_RESET"
        done
        printf '\n'
    done
}

pki_json_str() {
    printf '"%s"' "$(printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/\\t/g' -e 's/\r//g')"
}

# renders TSV records (stdin) as JSON
pki_render_json() {
    local s id st label detail first=1 overall=ok
    printf '{"generated":%s,"sections":[' "$(pki_json_str "$(date '+%Y-%m-%d %H:%M:%S')")"
    while IFS=$'\t' read -r s id st label detail; do
        [ -n "$s" ] || continue
        [ "$first" = 1 ] || printf ','
        first=0
        printf '{"section":%s,"id":%s,"state":%s,"label":%s,"detail":%s}' \
            "$(pki_json_str "$s")" "$(pki_json_str "$id")" "$(pki_json_str "$st")" \
            "$(pki_json_str "$label")" "$(pki_json_str "$detail")"
        overall=$(pki_worst "$overall" "$st")
    done
    printf '],"overall":%s}\n' "$(pki_json_str "$overall")"
}

# --------------------------------------------------------------- actions ----
# Actions are non-interactive by design: the TUI and the web UI both confirm
# before calling them. Every action returns non-zero on failure.

pki_restart_service() {
    local h="$1" svc="$2"
    pki_info "-> restart $svc on $h"
    if pki_ssh_sudo "$h" "systemctl restart $(pki_shq "$svc") && sleep 1 && systemctl is-active $(pki_shq "$svc")"; then
        pki_ok "$svc active on $h"
    else
        pki_err "$svc failed to restart on $h - check: systemctl status $svc"
        return 1
    fi
}

pki_require_files() {
    local f rc=0
    for f in "$@"; do
        [ -r "$f" ] || { pki_err "missing: $f"; rc=1; }
    done
    return $rc
}

act_renew() {
    if [ ! -x "$RENEW_SCRIPT" ]; then
        pki_err "renew script not executable: $RENEW_SCRIPT"
        return 1
    fi
    pki_info "== renew: $RENEW_SCRIPT $*"
    mkdir -p "$LOG_DIR"
    # renew-certs.sh writes its own log into $LOG_DIR; don't duplicate it here
    if "$RENEW_SCRIPT" "$@" 2>&1; then
        pki_ok "renewal finished (logs in $LOG_DIR)"
    else
        pki_err "renewal failed (see $LOG_DIR)"
        return 1
    fi
}

act_trust_push() {
    local h="$1" dst="$TRUST_ANCHOR_DIR/$ROOT_CA_NAME.crt" stage fp snippet
    pki_require_files "$ROOT_CA_CRT" || return 1
    fp=$(openssl x509 -in "$ROOT_CA_CRT" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
    pki_info "== trust-push $h  (root sha256 $fp)"

    stage="/tmp/.pki-root-anchor.$$.crt"
    if ! pki_scp_raw "$h" "$ROOT_CA_CRT" "$stage"; then
        pki_err "upload of the root CA to $h failed"; return 1
    fi

    # Adding an anchor must never remove one: during a cutover the certs still
    # in service are signed by the OLD root, and dropping it breaks LDAPS and
    # Samba the moment they reconnect. A superseded anchor is kept alongside
    # (still .crt, so still trusted) until trust-cleanup removes it.
    snippet=$(cat <<EOS
set -e
dst=$(pki_shq "$dst"); stage=$(pki_shq "$stage"); newfp=$(pki_shq "$fp")
mkdir -p $(pki_shq "$TRUST_ANCHOR_DIR")
if [ -f "\$dst" ]; then
    oldfp=\$(openssl x509 -in "\$dst" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
    if [ "\$oldfp" = "\$newfp" ]; then
        echo "anchor already current"
    else
        keep="$TRUST_ANCHOR_DIR/$ROOT_CA_NAME-superseded-\$(date +%Y%m%d-%H%M%S).crt"
        cp -a "\$dst" "\$keep"
        echo "previous anchor kept as \$keep (still trusted - remove with trust-cleanup)"
    fi
fi
install -o root -g root -m 0644 "\$stage" "\$dst"
rm -f "\$stage"
if command -v update-ca-certificates >/dev/null 2>&1; then update-ca-certificates
else update-ca-trust extract; fi
EOS
)
    if ! pki_ssh_sudo "$h" "$snippet"; then
        pki_err "trust store update failed on $h"
        pki_ssh "$h" "rm -f $(pki_shq "$stage")" >/dev/null 2>&1
        return 1
    fi

    # prove the anchor really landed rather than trusting the exit code
    if pki_ssh "$h" "openssl x509 -in $(pki_shq "$dst") -noout -fingerprint -sha256 2>/dev/null" 2>/dev/null \
       | grep -q "$fp"; then
        pki_ok "root CA trusted on $h: $dst"
    else
        pki_err "anchor on $h does not match the local root CA"
        return 1
    fi

    if pki_ssh "$h" "test -e $(pki_shq "$TRUST_ANCHOR_DIR/$STALE_CA_NAME")" 2>/dev/null; then
        pki_warn "$h still has stale anchor $TRUST_ANCHOR_DIR/$STALE_CA_NAME (ldap-fix repoints ldap.conf)"
    fi
}

# Remove anchors kept by trust-push. Run only once every service presents a
# cert from the new root - verify-tls tells you when that is true.
act_trust_cleanup() {
    local h="$1" snippet
    pki_info "== trust-cleanup $h"
    snippet=$(cat <<EOS
set -e
n=\$(ls -1 $TRUST_ANCHOR_DIR/$ROOT_CA_NAME-superseded-*.crt 2>/dev/null | wc -l)
if [ "\$n" = 0 ]; then echo "no superseded anchors"; exit 0; fi
ls -1 $TRUST_ANCHOR_DIR/$ROOT_CA_NAME-superseded-*.crt
rm -f $TRUST_ANCHOR_DIR/$ROOT_CA_NAME-superseded-*.crt
if command -v update-ca-certificates >/dev/null 2>&1; then update-ca-certificates --fresh >/dev/null
else update-ca-trust extract; fi
echo "removed \$n superseded anchor(s)"
EOS
)
    if pki_ssh_sudo "$h" "$snippet"; then
        pki_ok "trust store tidied on $h"
    else
        pki_err "trust-cleanup failed on $h"; return 1
    fi
}

# leaf + intermediate, in that order
pki_build_bundle() {
    local leaf="$1" out="$2"
    pki_require_files "$leaf" "$INT_CA_CRT" || return 1
    cat "$leaf" "$INT_CA_CRT" >"$out"
}

act_webmin_push() {
    local h="$1" crt key tmpb
    pki_host_has_role "$h" webmin || { pki_err "$h has no webmin role"; return 1; }
    crt=$(pki_host_cert "$h"); key=$(pki_host_key "$h")
    pki_require_files "$crt" "$key" || return 1
    pki_info "== webmin-push $h"
    tmpb=$(mktemp)
    pki_build_bundle "$crt" "$tmpb" || { rm -f "$tmpb"; return 1; }
    pki_info "-> miniserv.cert = leaf + intermediate ($(pki_tls_chain_len "$tmpb") certs)"
    pki_scp_to "$h" "$tmpb" "$WEBMIN_CERT" 0600 || { rm -f "$tmpb"; return 1; }
    rm -f "$tmpb"
    pki_scp_to "$h" "$key" "$WEBMIN_KEY" 0600 || return 1
    act_webmin_fix "$h" || return 1
    pki_restart_service "$h" "$WEBMIN_SERVICE"
}

# Fixes the miniserv.conf that points at /var/lib/samba/private/tls after an AD join.
act_webmin_fix() {
    local h="$1"
    pki_host_has_role "$h" webmin || { pki_err "$h has no webmin role"; return 1; }
    pki_info "== webmin-fix $h ($WEBMIN_CONF)"
    local snippet
    snippet=$(cat <<EOS
set -e
conf=$WEBMIN_CONF
[ -f "\$conf" ] || { echo "ERR missing \$conf" >&2; exit 1; }
echo "before: \$(grep -E '^(keyfile|certfile|extracas|ssl)=' "\$conf" | tr '\n' ' ')"
cp -a "\$conf" "\$conf.bak.\$(date +%Y%m%d-%H%M%S)"
sed -i -e 's|^keyfile=.*|keyfile=$WEBMIN_KEY|' \
       -e 's|^certfile=.*|certfile=$WEBMIN_CERT|' \
       -e '/^extracas=/d' "\$conf"
grep -q '^keyfile='  "\$conf" || echo 'keyfile=$WEBMIN_KEY'   >>"\$conf"
grep -q '^certfile=' "\$conf" || echo 'certfile=$WEBMIN_CERT' >>"\$conf"
grep -q '^ssl=1'     "\$conf" || { sed -i '/^ssl=/d' "\$conf"; echo 'ssl=1' >>"\$conf"; }
chown root:root "\$conf"; chmod 600 "\$conf"
echo "after:  \$(grep -E '^(keyfile|certfile|ssl)=' "\$conf" | tr '\n' ' ')"
EOS
)
    if pki_ssh_sudo "$h" "$snippet"; then
        pki_ok "miniserv.conf points at $WEBMIN_DIR on $h"
    else
        pki_err "webmin-fix failed on $h"
        return 1
    fi
}

# Samba refuses to start unless its TLS files are root:root.
act_samba_fix() {
    local h="$1"
    pki_host_has_role "$h" samba || { pki_err "$h has no samba role"; return 1; }
    pki_info "== samba-fix $h ($SAMBA_TLS_DIR)"
    local snippet
    snippet=$(cat <<EOS
set -e
d=$SAMBA_TLS_DIR
[ -d "\$d" ] || { echo "ERR missing \$d" >&2; exit 1; }
chown -R root:root "\$d"
chmod 755 "\$d"; chmod 644 "\$d"/ca.pem "\$d"/cert.pem 2>/dev/null || true
chmod 600 "\$d"/key.pem 2>/dev/null || true
ls -l "\$d"
EOS
)
    pki_ssh_sudo "$h" "$snippet" || { pki_err "samba-fix failed on $h"; return 1; }
    pki_restart_service "$h" "$SAMBA_SERVICE"
}

act_ldap_fix() {
    local h="$1" anchor="$TRUST_ANCHOR_DIR/$ROOT_CA_NAME.crt"
    pki_info "== ldap-fix $h ($LDAP_CONF -> $anchor)"
    local snippet
    snippet=$(cat <<EOS
set -e
f=$LDAP_CONF
mkdir -p "\$(dirname "\$f")"; touch "\$f"
echo "before: \$(grep -iE '^[[:space:]]*TLS_CACERT' "\$f" | tr '\n' ' ')"
[ -r $anchor ] || { echo "ERR anchor missing: $anchor - run trust-push first" >&2; exit 1; }
cp -a "\$f" "\$f.bak.\$(date +%Y%m%d-%H%M%S)"
sed -i -E '/^[[:space:]]*TLS_CACERT(DIR)?[[:space:]]/Id' "\$f"
{ echo "TLS_CACERT $anchor"; echo "TLS_CACERTDIR /etc/ssl/certs"; } >>"\$f"
chmod 644 "\$f"
echo "after:  \$(grep -iE '^[[:space:]]*TLS_CACERT' "\$f" | tr '\n' ' ')"
EOS
)
    if pki_ssh_sudo "$h" "$snippet"; then
        pki_ok "ldap.conf trust anchor corrected on $h"
    else
        pki_err "ldap-fix failed on $h"
        return 1
    fi
}

act_deploy() {
    local h="$1" crt key fqdn tmpb rc=0
    pki_host_valid "$h" || { pki_err "unknown host: $h"; return 1; }
    crt=$(pki_host_cert "$h"); key=$(pki_host_key "$h"); fqdn=$(pki_host_fqdn "$h")
    pki_ca_ready || { pki_ca_missing_msg; return 1; }
    if ! pki_require_files "$crt" "$key"; then
        pki_err "$fqdn has no certificate yet - run: ./renew-certs.sh --force"
        return 1
    fi
    pki_info "== deploy $h ($fqdn) roles: $(pki_host_roles "$h")"

    if pki_host_has_role "$h" apache; then
        pki_info "-> apache: $APACHE_CERT_DIR"
        tmpb=$(mktemp); pki_build_bundle "$crt" "$tmpb" || { rm -f "$tmpb"; return 1; }
        pki_ssh_sudo "$h" "mkdir -p $(pki_shq "$APACHE_CERT_DIR") && chmod 750 $(pki_shq "$APACHE_CERT_DIR")" || rc=1
        pki_scp_to "$h" "$crt"          "$APACHE_CERT_DIR/$fqdn.crt"           0644 || rc=1
        pki_scp_to "$h" "$tmpb"         "$APACHE_CERT_DIR/$fqdn-fullchain.crt" 0644 || rc=1
        pki_scp_to "$h" "$key"          "$APACHE_CERT_DIR/$fqdn.key"           0600 || rc=1
        pki_scp_to "$h" "$INT_CA_CRT"   "$APACHE_CERT_DIR/chain.crt"           0644 || rc=1
        rm -f "$tmpb"
        if pki_ssh_sudo "$h" "apache2ctl configtest"; then
            pki_ssh_sudo "$h" "systemctl reload $(pki_shq "$APACHE_SERVICE")" && pki_ok "apache reloaded on $h" || rc=1
        else
            pki_err "apache configtest failed on $h - NOT reloading"; rc=1
        fi
    fi

    if pki_host_has_role "$h" samba; then
        pki_info "-> samba: $SAMBA_TLS_DIR"
        tmpb=$(mktemp); cat "$INT_CA_CRT" "$ROOT_CA_CRT" >"$tmpb"
        pki_ssh_sudo "$h" "mkdir -p $(pki_shq "$SAMBA_TLS_DIR")" || rc=1
        pki_scp_to "$h" "$crt"   "$SAMBA_TLS_DIR/cert.pem" 0644 || rc=1
        pki_scp_to "$h" "$key"   "$SAMBA_TLS_DIR/key.pem"  0600 || rc=1
        pki_scp_to "$h" "$tmpb"  "$SAMBA_TLS_DIR/ca.pem"   0644 || rc=1
        rm -f "$tmpb"
        act_samba_fix "$h" || rc=1     # chown root:root + restart, always
    fi

    if pki_host_has_role "$h" dns; then
        pki_info "-> technitium: $TECHNITIUM_PFX"
        if [ -z "$TECHNITIUM_PFX_PASS" ]; then
            pki_warn "TECHNITIUM_PFX_PASS unset in pki.conf - skipping DNS cert"
        else
            tmpb=$(mktemp --suffix=.pfx)
            if openssl pkcs12 -export -out "$tmpb" -inkey "$key" -in "$crt" \
                 -certfile "$INT_CA_CRT" -passout "pass:$TECHNITIUM_PFX_PASS" 2>/dev/null; then
                pki_scp_to "$h" "$tmpb" "$TECHNITIUM_PFX" 0600 || rc=1
                pki_ssh_sudo "$h" "chown $(pki_shq "$TECHNITIUM_USER"):$(pki_shq "$TECHNITIUM_USER") $(pki_shq "$TECHNITIUM_PFX")" || rc=1
                pki_restart_service "$h" "$TECHNITIUM_SERVICE" || rc=1
            else
                pki_err "pkcs12 export failed"; rc=1
            fi
            rm -f "$tmpb"
        fi
    fi

    if pki_host_has_role "$h" webmin; then
        act_webmin_push "$h" || rc=1
    fi

    [ $rc = 0 ] && pki_ok "deploy $h complete" || pki_err "deploy $h finished with errors"
    return $rc
}

act_nextcloud_certcheck() {
    local mode="${1:-auto}" h cur
    h=$(pki_nc_host) || { pki_err "no host has the nextcloud role"; return 1; }
    cur=$(pki_nc_certcheck_get "$h")
    pki_info "== nextcloud certcheck ($mode) on $h - turnOffCertCheck currently: $cur"
    case "$mode" in
        auto)
            if pki_nc_trust_ok "$h"; then
                pki_ok "trust to $(pki_nc_probe_url) verifies - enforcing cert checks"
                mode=enforce
            else
                pki_warn "trust to $(pki_nc_probe_url) fails - enabling bypass so Nextcloud keeps working"
                mode=bypass
            fi ;;
    esac
    case "$mode" in
        enforce|on)
            pki_nc_occ "$h" "config:system:delete turnOffCertCheck" >/dev/null 2>&1
            pki_ok "turnOffCertCheck cleared (cert checking ON)" ;;
        bypass|off)
            pki_nc_occ "$h" "config:system:set turnOffCertCheck --value=true --type=boolean" >/dev/null \
                && pki_ok "turnOffCertCheck=true (cert checking OFF)" \
                || { pki_err "occ set failed"; return 1; } ;;
        *) pki_err "bad mode: $mode (auto|enforce|bypass)"; return 1 ;;
    esac
}

act_verify_tls() {
    local only="${1:-}" h addr fqdn p tmp len days
    for h in $HOSTS; do
        [ -n "$only" ] && [ "$only" != "$h" ] && continue
        addr=$(pki_host_addr "$h"); fqdn=$(pki_host_fqdn "$h")
        printf '%s== %s (%s)%s\n' "$C_HEAD" "$h" "$addr" "$C_RESET"
        for p in $(pki_role_ports "$h"); do
            [ "$p" = 53 ] && continue
            tmp=$(mktemp)
            if ! pki_tls_fetch "$addr" "$p" "$fqdn" "$tmp"; then
                printf '  %-6s %sno TLS answer%s\n' ":$p" "$C_ERR" "$C_RESET"; rm -f "$tmp"; continue
            fi
            len=$(pki_tls_chain_len "$tmp"); days=$(pki_tls_days "$tmp")
            if pki_tls_verify_ok "$tmp"; then
                printf '  %-6s %sOK%s   chain=%s  %sd  %s\n' \
                    ":$p" "$C_OK" "$C_RESET" "$len" "${days:-?}" "$(pki_tls_subject "$tmp")"
            else
                printf '  %-6s %sFAIL%s chain=%s  %s\n' \
                    ":$p" "$C_ERR" "$C_RESET" "$len" "$(pki_tls_verify_msg "$tmp")"
            fi
            printf '         issuer: %s\n' "$(pki_tls_issuer "$tmp")"
            rm -f "$tmp"
        done
    done
}

act_logs() {
    local n="${1:-60}" f
    case "$n" in ''|*[!0-9]*) n=60 ;; esac
    [ -d "$LOG_DIR" ] || { pki_err "no log dir: $LOG_DIR"; return 1; }
    for f in "$MANAGER_LOG" $(ls -1t "$LOG_DIR"/renew-*.log 2>/dev/null | head -3); do
        [ -r "$f" ] || continue
        printf '%s== %s (last %s)%s\n' "$C_HEAD" "$f" "$n" "$C_RESET"
        tail -n "$n" "$f"
        printf '\n'
    done
}

# ------------------------------------------------------------ dispatcher ----
# Single validated entry point. The web UI never builds a command line.

PKI_ACTIONS="status preflight renew deploy deploy-all trust-push trust-push-all webmin-push
webmin-push-all webmin-fix webmin-fix-all ldap-fix ldap-fix-all samba-fix
nextcloud-certcheck verify-tls logs issue issue-all trust-cleanup
trust-cleanup-all yk-info yk-slot yk-export-cert yk-retries
yk-pkcs11 yk-test yk-sign-intermediate yk-change-pin yk-change-puk yk-unblock-pin
yk-change-mgmt"

# Refused in the web UI: these prompt for a PIN or need a physical touch.
PKI_TTY_ACTIONS="yk-test yk-sign-intermediate yk-change-pin yk-change-puk yk-unblock-pin yk-change-mgmt"
pki_action_is_tty() { case " $PKI_TTY_ACTIONS " in *" $1 "*) return 0 ;; esac; return 1; }

pki_action_valid() { case " $(printf '%s' "$PKI_ACTIONS" | tr '\n' ' ') " in *" $1 "*) return 0 ;; esac; return 1; }

pki_run_action() {
    local action="$1" arg="${2:-}" h rc=0
    pki_action_valid "$action" || { pki_err "unknown action: $action"; return 2; }
    case "$action" in
        deploy|trust-push|webmin-push|webmin-fix|ldap-fix|samba-fix|issue|trust-cleanup)
            pki_host_valid "$arg" || { pki_err "action $action needs a valid host ($HOSTS)"; return 2; } ;;
        nextcloud-certcheck)
            case "${arg:-auto}" in auto|enforce|bypass|on|off) ;; *) pki_err "bad mode: $arg"; return 2 ;; esac ;;
        verify-tls)
            [ -n "$arg" ] && { pki_host_valid "$arg" || { pki_err "unknown host: $arg"; return 2; }; } ;;
        logs)
            case "$arg" in ''|*[!0-9]*) arg=60 ;; esac ;;
        yk-slot|yk-export-cert|yk-test)
            case "${arg:-$YUBIKEY_SLOT}" in 9a|9c|9d|9e) ;; *) pki_err "bad slot: $arg (9a|9c|9d|9e)"; return 2 ;; esac ;;
    esac
    # a PIN prompt with no terminal would just hang the web UI
    if pki_action_is_tty "$action" && { [ "${PKI_NONINTERACTIVE:-0}" = 1 ] || [ ! -t 0 ]; }; then
        pki_err "$action requires a terminal (PIN/touch) - run it from the TUI on the console"
        return 2
    fi
    case "$action" in
        _never_) ;;
    esac
    # One clear message instead of the same complaint once per host.
    case "$action" in
        deploy|deploy-all|issue|issue-all|webmin-push|webmin-push-all)
            pki_ca_ready || { pki_ca_missing_msg; return 1; } ;;
        trust-push|trust-push-all)
            [ -r "$ROOT_CA_CRT" ] || { pki_ca_missing_msg; return 1; } ;;
    esac
    pki_log "action=$action arg=$arg"
    case "$action" in
        status)              pki_collect_status | pki_render_text ;;
        preflight)           act_preflight ;;
        renew)               act_renew ;;
        deploy)              act_deploy "$arg" ;;
        deploy-all)          for h in $HOSTS; do act_deploy "$h" || rc=1; done ;;
        trust-push)          act_trust_push "$arg" ;;
        trust-push-all)      for h in $HOSTS; do act_trust_push "$h" || rc=1; done ;;
        webmin-push)         act_webmin_push "$arg" ;;
        webmin-push-all)     for h in $HOSTS; do pki_host_has_role "$h" webmin && { act_webmin_push "$h" || rc=1; }; done ;;
        webmin-fix)          act_webmin_fix "$arg" ;;
        webmin-fix-all)      for h in $HOSTS; do pki_host_has_role "$h" webmin && { act_webmin_fix "$h" || rc=1; }; done ;;
        ldap-fix)            act_ldap_fix "$arg" ;;
        ldap-fix-all)        for h in $HOSTS; do act_ldap_fix "$h" || rc=1; done ;;
        samba-fix)           act_samba_fix "$arg" ;;
        nextcloud-certcheck) act_nextcloud_certcheck "${arg:-auto}" ;;
        verify-tls)          act_verify_tls "$arg" ;;
        logs)                act_logs "$arg" ;;
        issue)               pki_issue_cert "$arg" "$LEAF_DAYS" ;;
        issue-all)           for h in $HOSTS; do pki_issue_cert "$h" "$LEAF_DAYS" || rc=1; done ;;
        trust-cleanup)       act_trust_cleanup "$arg" ;;
        trust-cleanup-all)   for h in $HOSTS; do act_trust_cleanup "$h" || rc=1; done ;;
        yk-info)             act_yk_info ;;
        yk-slot)             act_yk_slot "${arg:-$YUBIKEY_SLOT}" ;;
        yk-export-cert)      act_yk_export_cert "${arg:-$YUBIKEY_SLOT}" ;;
        yk-retries)          act_yk_retries ;;
        yk-pkcs11)           act_yk_pkcs11 ;;
        yk-test)             act_yk_test "${arg:-$YUBIKEY_SLOT}" ;;
        yk-sign-intermediate) act_yk_sign_intermediate "$arg" ;;
        yk-change-pin)       act_yk_change_pin ;;
        yk-change-puk)       act_yk_change_puk ;;
        yk-unblock-pin)      act_yk_unblock_pin ;;
        yk-change-mgmt)      act_yk_change_mgmt ;;
    esac || rc=$?
    pki_log "action=$action arg=$arg rc=$rc"
    return $rc
}

# ------------------------------------------------------ yubikey management --
# The root CA private key lives on the YubiKey (slot 9c) and never leaves it.
# The PIN is NEVER stored in pki.conf and never accepted over the web UI:
# ykman prompts on the terminal, so PIN-touching actions are TUI-only.

pki_yk_ready() {
    command -v ykman >/dev/null 2>&1 || { pki_err "ykman not installed (apt install yubikey-manager)"; return 1; }
    timeout 15 ykman piv info >/dev/null 2>&1 || { pki_err "no YubiKey detected"; return 1; }
}

# ykman renamed these subcommands between 4.x and 5.x - support both
pki_yk_export_cert() {  # slot outfile
    local slot="$1" out="$2"
    timeout 60 ykman piv certificates export "$slot" "$out" 2>/dev/null && return 0
    timeout 60 ykman piv export-certificate "$slot" "$out" 2>/dev/null && return 0
    return 1
}

pki_yk_import_cert() {  # slot infile
    local slot="$1" in="$2"
    pki_yk_mgmt_args
    # PIV_TIMEOUT is generous: this prompts for the management key unless
    # YK_MGMT_KEY is set, and a person has to type it.
    if [ "$(pki_yk_cert_api)" = new ]; then
        timeout "${PIV_TIMEOUT:-300}" ykman piv certificates import "${YK_MGMT[@]}" "$slot" "$in"
    else
        timeout "${PIV_TIMEOUT:-300}" ykman piv import-certificate "${YK_MGMT[@]}" "$slot" "$in"
    fi
}

# ykman 4.x prints "Slot 9c", 5.x prints "Slot 9C". A guard that protects a
# root CA key must not hinge on that, so fall back to asking for the slot's
# certificate: a slot with no key cannot produce one.
pki_yk_slot_occupied() {  # slot -> 0 if a key is present
    local slot="${1:-$YUBIKEY_SLOT}" out tmp rc=1
    out=$(timeout 15 ykman piv info 2>/dev/null) || return 1
    printf '%s' "$out" | grep -qi "^Slot ${slot}\b" && return 0
    tmp=$(mktemp)
    pki_yk_export_cert "$slot" "$tmp" 2>/dev/null && [ -s "$tmp" ] \
        && openssl x509 -in "$tmp" -noout >/dev/null 2>&1 && rc=0
    rm -f "$tmp"
    return $rc
}

act_yk_info() {
    pki_yk_ready || return 1
    pki_info "== yubikey"
    timeout 15 ykman list 2>&1
    printf '\n'
    timeout 15 ykman piv info 2>&1
}

act_yk_slot() {
    local slot="${1:-$YUBIKEY_SLOT}" tmp
    pki_yk_ready || return 1
    case "$slot" in 9a|9c|9d|9e) ;; *) pki_err "bad slot: $slot (9a|9c|9d|9e)"; return 2 ;; esac
    tmp=$(mktemp)
    if ! pki_yk_export_cert "$slot" "$tmp"; then
        pki_err "no certificate in slot $slot"
        rm -f "$tmp"; return 1
    fi
    pki_info "== slot $slot certificate"
    openssl x509 -in "$tmp" -noout -subject -issuer -serial -dates -fingerprint -sha256 2>&1
    printf '\n'
    pki_info "-- extensions"
    openssl x509 -in "$tmp" -noout -ext basicConstraints,keyUsage,subjectKeyIdentifier 2>/dev/null \
        | sed 's/^/   /' || pki_warn "no X509v3 extensions present"
    printf '\n'
    # the one thing that decides whether this cert can sign an intermediate
    if openssl x509 -in "$tmp" -noout -text 2>/dev/null | grep -q 'CA:TRUE'; then
        pki_ok "usable as a CA (basicConstraints CA:TRUE)"
    else
        pki_err "NOT usable as a CA - no basicConstraints CA:TRUE"
        pki_err "a cert without it cannot sign an intermediate; the root must be recreated"
        rm -f "$tmp"; return 1
    fi
    rm -f "$tmp"
}

# Copy the CA cert off the key into the local tree (public data - no PIN needed).
act_yk_export_cert() {
    local slot="${1:-$YUBIKEY_SLOT}" tmp
    pki_yk_ready || return 1
    tmp=$(mktemp)
    if ! pki_yk_export_cert "$slot" "$tmp"; then
        pki_err "no certificate in slot $slot"; rm -f "$tmp"; return 1
    fi
    if ! openssl x509 -in "$tmp" -noout >/dev/null 2>&1; then
        pki_err "slot $slot did not return a valid certificate"; rm -f "$tmp"; return 1
    fi
    mkdir -p "$ROOT_CA_DIR"
    if [ -f "$ROOT_CA_CRT" ] && ! cmp -s "$tmp" "$ROOT_CA_CRT"; then
        cp -a "$ROOT_CA_CRT" "$ROOT_CA_CRT.bak.$(date +%Y%m%d-%H%M%S)"
        pki_warn "existing $ROOT_CA_CRT differed - backed up"
    fi
    install -m 0644 "$tmp" "$ROOT_CA_CRT"
    rm -f "$tmp"
    pki_ok "root CA cert written: $ROOT_CA_CRT ($(pki_cert_days "$ROOT_CA_CRT")d left)"
}

act_yk_retries() {
    pki_yk_ready || return 1
    timeout 15 ykman piv info 2>&1 | grep -iE 'tries|retries|PIN|PUK' || pki_info "no retry counters reported"
}

# Prove the slot key still signs - catches a wiped/locked key before renewal day.
act_yk_test() {
    local slot="${1:-$YUBIKEY_SLOT}" tmp sig data pub rc=0
    pki_yk_ready || return 1
    pki_tty_required "yk-test" || return 2
    tmp=$(mktemp -d); data="$tmp/data"; sig="$tmp/sig"; pub="$tmp/pub.pem"
    date +%s%N > "$data"
    if ! pki_yk_export_cert "$slot" "$tmp/cert.pem"; then
        pki_err "no certificate in slot $slot"; rm -rf "$tmp"; return 1
    fi
    openssl x509 -in "$tmp/cert.pem" -noout -pubkey > "$pub" 2>/dev/null
    pki_info "== test-sign with slot $slot (PIN + touch may be required)"
    if timeout 60 ykman piv keys sign -s "$slot" -a SHA256 - "$sig" < "$data" 2>/dev/null \
       || timeout 60 ykman piv sign-key -s "$slot" - "$sig" < "$data" 2>/dev/null; then
        if openssl dgst -sha256 -verify "$pub" -signature "$sig" "$data" >/dev/null 2>&1; then
            pki_ok "slot $slot signs and verifies against its own certificate"
        else
            pki_err "signature did NOT verify - slot cert and private key disagree"; rc=1
        fi
    else
        pki_err "signing failed (wrong PIN, no touch, or empty slot)"; rc=1
    fi
    rm -rf "$tmp"; return $rc
}

# The reason the key exists: sign the intermediate CSR with the offline root.
act_yk_sign_intermediate() {
    local csr="${1:-$INT_CA_DIR/$INT_CA_NAME.csr}" ext out
    pki_yk_ready || return 1
    pki_tty_required "yk-sign-intermediate" || return 2
    pki_require_files "$csr" "$ROOT_CA_CRT" || return 1
    pki_pkcs11_detect && pki_pkcs11_resolve_key "$YUBIKEY_SLOT" >/dev/null 2>&1
    if [ ! -r "$PKCS11_MODULE" ]; then
        pki_err "PKCS#11 module not found: $PKCS11_MODULE"
        pki_err "install opensc + libengine-pkcs11-openssl, or set PKCS11_MODULE in pki.conf"
        return 1
    fi
    if ! openssl engine pkcs11 >/dev/null 2>&1; then
        pki_err "openssl has no pkcs11 engine (apt install libengine-pkcs11-openssl)"
        return 1
    fi
    ext=$(mktemp); out="$INT_CA_DIR/$INT_CA_NAME.crt"
    cat > "$ext" <<EOX
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EOX
    pki_info "== signing $(basename "$csr") with the YubiKey root key (PIN + touch)"
    [ -f "$out" ] && cp -a "$out" "$out.bak.$(date +%Y%m%d-%H%M%S)"
    if openssl x509 -req -sha256 -engine pkcs11 -CAkeyform engine \
         -in "$csr" -CA "$ROOT_CA_CRT" -CAkey "$YK_ROOT_KEY_URI" \
         -CAcreateserial -days "$INT_CA_DAYS" -extfile "$ext" -out "$out" 2>&1; then
        rm -f "$ext"
        if openssl verify -CAfile "$ROOT_CA_CRT" "$out" >/dev/null 2>&1; then
            pki_ok "intermediate signed: $out ($(pki_cert_days "$out")d)"
        else
            pki_err "signed but does not verify against $ROOT_CA_CRT"; return 1
        fi
    else
        rm -f "$ext"
        pki_err "signing failed - check YK_ROOT_KEY_URI ($YK_ROOT_KEY_URI) and the PIN"
        return 1
    fi
}

act_yk_change_pin()  { pki_yk_ready || return 1; pki_tty_required yk-change-pin  || return 2; pki_info "== change PIV PIN";  timeout 120 ykman piv access change-pin 2>&1 || timeout 120 ykman piv change-pin 2>&1; }
act_yk_change_puk()  { pki_yk_ready || return 1; pki_tty_required yk-change-puk  || return 2; pki_info "== change PIV PUK";  timeout 120 ykman piv access change-puk 2>&1 || timeout 120 ykman piv change-puk 2>&1; }
act_yk_unblock_pin() { pki_yk_ready || return 1; pki_tty_required yk-unblock-pin || return 2; pki_info "== unblock PIN with PUK"; timeout 120 ykman piv access unblock-pin 2>&1 || timeout 120 ykman piv unblock-pin 2>&1; }
act_yk_change_mgmt() { pki_yk_ready || return 1; pki_tty_required yk-change-mgmt || return 2; pki_info "== change management key"; timeout 120 ykman piv access change-management-key --touch 2>&1 || timeout 120 ykman piv change-management-key --touch 2>&1; }

# =========================================================== CA creation ====
# Root CA key is generated on the YubiKey and never leaves it. The intermediate
# key lives on disk so routine renewals need no PIN and no touch: only root
# operations require the hardware.

# Sets PKCS11_MODE to engine | provider | none.
pki_pkcs11_detect() {
    PKCS11_MODE=none
    if openssl engine pkcs11 >/dev/null 2>&1; then
        PKCS11_MODE=engine
    elif openssl list -providers 2>/dev/null | grep -qi 'pkcs11'; then
        PKCS11_MODE=provider
    fi
    [ "$PKCS11_MODE" != none ]
}

pki_pkcs11_hint() {
    pki_err "no PKCS#11 support in openssl - the YubiKey cannot sign"
    pki_err "install one of:  apt install libengine-pkcs11-openssl opensc"
    pki_err "             or: apt install pkcs11-provider opensc"
}

# Arg arrays for openssl. `req`/`ca` take -keyform, `x509 -req` takes -CAkeyform.
pki_pkcs11_key_args() {
    case "$PKCS11_MODE" in
        engine)   PK11_KEY=(-engine pkcs11 -keyform engine) ;;
        provider) PK11_KEY=(-provider pkcs11 -provider default) ;;
        *)        PK11_KEY=() ;;
    esac
}
pki_pkcs11_cakey_args() {
    case "$PKCS11_MODE" in
        engine)   PK11_CAKEY=(-engine pkcs11 -CAkeyform engine) ;;
        provider) PK11_CAKEY=(-provider pkcs11 -provider default) ;;
        *)        PK11_CAKEY=() ;;
    esac
}

pki_genkey() {  # outfile [algo]
    local out="$1" algo="${2:-$KEY_ALGO}"
    mkdir -p "$(dirname "$out")"
    case "$algo" in
        rsa2048) openssl genrsa -out "$out" 2048 2>/dev/null ;;
        rsa4096) openssl genrsa -out "$out" 4096 2>/dev/null ;;
        ecp256)  openssl ecparam -name prime256v1 -genkey -noout -out "$out" 2>/dev/null ;;
        ecp384)  openssl ecparam -name secp384r1 -genkey -noout -out "$out" 2>/dev/null ;;
        *) pki_err "unknown KEY_ALGO: $algo"; return 1 ;;
    esac || { pki_err "key generation failed: $out"; return 1; }
    chmod 600 "$out"
}

# SAN list for a host: fqdn, short name, address, plus HOST_<h>_SANS extras.
pki_host_sans() {
    local h="$1" fqdn addr extra s sans v
    fqdn=$(pki_host_fqdn "$h"); addr=$(pki_host_addr "$h")
    sans="DNS:$fqdn,DNS:$h"
    case "$addr" in
        ''|*[!0-9.]*) ;;
        *) sans="$sans,IP:$addr" ;;
    esac
    v="HOST_${h}_SANS"; extra="${!v:-}"
    for s in $extra; do
        case "$s" in
            DNS:*|IP:*|email:*|URI:*) sans="$sans,$s" ;;
            *[!0-9.]*)                sans="$sans,DNS:$s" ;;
            *)                        sans="$sans,IP:$s" ;;
        esac
    done
    printf '%s' "$sans"
}

pki_leaf_extfile() {  # host outfile
    local h="$1" out="$2"
    cat > "$out" <<EOX
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=$(pki_host_sans "$h")
EOX
}

pki_int_extfile() {  # outfile
    cat > "$1" <<'EOX'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EOX
}

pki_passin_args() {  # populates PASSIN for the intermediate key
    if [ -n "$INT_CA_KEY_PASS" ]; then
        PKI_INT_PASS="$INT_CA_KEY_PASS"; export PKI_INT_PASS
        PASSIN=(-passin env:PKI_INT_PASS)
    else
        PASSIN=()
    fi
}

pki_next_serial() {
    mkdir -p "$(dirname "$CA_SERIAL")"
    [ -s "$CA_SERIAL" ] || printf '1000\n' > "$CA_SERIAL"
    printf '%s' "$(cat "$CA_SERIAL")"
}

pki_verify_chain() {  # leaf-cert
    openssl verify -CAfile "$ROOT_CA_CRT" -untrusted "$INT_CA_CRT" "$1" >/dev/null 2>&1
}

# Issue (or re-issue) the service cert for one host, signed by the intermediate.
# No YubiKey and no PIN: this is the path automation uses.
pki_issue_cert() {
    local h="$1" days="${2:-$LEAF_DAYS}" rotate="${3:-0}"
    local fqdn crt key csr ext
    fqdn=$(pki_host_fqdn "$h")
    crt=$(pki_host_cert "$h"); key=$(pki_host_key "$h")
    csr="$CERT_DIR/$fqdn.csr"; ext=$(mktemp)

    pki_ca_ready || { pki_ca_missing_msg; rm -f "$ext"; return 1; }
    mkdir -p "$CERT_DIR"

    if [ ! -s "$key" ] || [ "$rotate" = 1 ]; then
        pki_info "-> new key ($KEY_ALGO): $key"
        pki_genkey "$key" || { rm -f "$ext"; return 1; }
    else
        pki_info "-> reusing key: $key"
    fi

    if ! openssl req -new -key "$key" -subj "/CN=$fqdn" -out "$csr" 2>/dev/null; then
        pki_err "CSR failed for $fqdn"; rm -f "$ext"; return 1
    fi

    pki_leaf_extfile "$h" "$ext"
    pki_passin_args
    [ -f "$crt" ] && cp -a "$crt" "$crt.bak.$(date +%Y%m%d-%H%M%S)"
    if ! openssl x509 -req -sha256 -in "$csr" \
            -CA "$INT_CA_CRT" -CAkey "$INT_CA_KEY" "${PASSIN[@]}" \
            -CAserial "$CA_SERIAL" -CAcreateserial \
            -days "$days" -extfile "$ext" -out "$crt" 2>/dev/null; then
        pki_err "signing failed for $fqdn - check the intermediate key/passphrase"
        rm -f "$ext"; return 1
    fi
    rm -f "$ext" "$csr"
    chmod 644 "$crt"

    if pki_verify_chain "$crt"; then
        pki_ok "$fqdn issued, ${days}d, SAN: $(pki_host_sans "$h")"
    else
        pki_err "$fqdn issued but does NOT verify against the root - not deploying this"
        return 1
    fi
}

# ========================================================== preflight =======

# Classify why ssh to a host does or does not work, so the fix is obvious.
pki_ssh_probe() {  # host -> ok|closed|auth|hostkey|timeout|fail
    local h="$1" out rc
    if ! pki_tcp "$(pki_host_addr "$h")" "$SSH_PORT" 3; then printf 'closed'; return; fi
    out=$(pki_ssh "$h" true 2>&1); rc=$?
    [ "$rc" = 0 ] && { printf 'ok'; return; }
    case "$out" in
        *"Permission denied"*)            printf 'auth' ;;
        *"Host key verification failed"*) printf 'hostkey' ;;
        *"Connection timed out"*)         printf 'timeout' ;;
        *)                                printf 'fail' ;;
    esac
}

pki_ca_ready() {
    [ -r "$ROOT_CA_CRT" ] && [ -r "$INT_CA_CRT" ] && [ -r "$INT_CA_KEY" ]
}

pki_ca_missing_msg() {
    pki_err "no CA yet - nothing can be issued or deployed"
    [ -r "$ROOT_CA_CRT" ] || pki_err "  missing root cert:   $ROOT_CA_CRT"
    [ -r "$INT_CA_CRT" ]  || pki_err "  missing intermediate: $INT_CA_CRT"
    [ -r "$INT_CA_KEY" ]  || pki_err "  missing intermediate key: $INT_CA_KEY"
    pki_err "create it:  ./pki-init.sh --dry-run   then   ./pki-init.sh"
}

# Check everything a cutover needs, change nothing, and say how to fix what fails.
act_preflight() {
    local ok=0 bad=0 warn=0
    mark() {  # state label fix
        case "$1" in
            ok)   printf '  %s[ OK ]%s %s\n' "$C_OK" "$C_RESET" "$2"; ok=$((ok+1)) ;;
            warn) printf '  %s[WARN]%s %s\n' "$C_WARN" "$C_RESET" "$2"; warn=$((warn+1))
                  [ -n "${3:-}" ] && printf '         %s%s%s\n' "$C_DIM" "$3" "$C_RESET" ;;
            *)    printf '  %s[FAIL]%s %s\n' "$C_ERR" "$C_RESET" "$2"; bad=$((bad+1))
                  [ -n "${3:-}" ] && printf '         %s-> %s%s\n' "$C_DIM" "$3" "$C_RESET" ;;
        esac
    }

    printf '%sCONFIG%s\n' "$C_HEAD" "$C_RESET"
    if [ "$PKI_CONF_LOADED" = 1 ]; then
        case "$PKI_CONF_PERM" in
            600|400) mark ok "pki.conf loaded ($PKI_CONF)" ;;
            *) mark warn "pki.conf mode $PKI_CONF_PERM ($PKI_CONF)" "chmod 600 $PKI_CONF" ;;
        esac
    else
        mark fail "no pki.conf at $PKI_CONF" "cp pki.conf.example $PKI_CONF && chmod 600 $PKI_CONF"
    fi

    printf '\n%sTOOLS%s\n' "$C_HEAD" "$C_RESET"
    local t
    for t in openssl ssh scp; do
        command -v "$t" >/dev/null 2>&1 && mark ok "$t" \
            || mark fail "$t missing" "sudo apt install openssh-client openssl"
    done
    command -v ykman >/dev/null 2>&1 && mark ok "ykman" \
        || mark warn "ykman missing (only needed to create/manage the root CA)" "sudo apt install yubikey-manager"
    if pki_pkcs11_detect; then mark ok "openssl PKCS#11 ($PKCS11_MODE)"
    else mark warn "no openssl PKCS#11 (only needed for root CA operations)" \
         "sudo apt install libengine-pkcs11-openssl opensc"; fi

    printf '\n%sCA%s\n' "$C_HEAD" "$C_RESET"
    if pki_ca_ready; then
        mark ok "root CA  $(basename "$ROOT_CA_CRT") ($(pki_cert_days "$ROOT_CA_CRT")d)"
        mark ok "intermediate ($(pki_cert_days "$INT_CA_CRT")d)"
        if openssl verify -CAfile "$ROOT_CA_CRT" "$INT_CA_CRT" >/dev/null 2>&1; then
            mark ok "intermediate verifies against the root"
        else
            mark fail "intermediate does not verify against the root" "rebuild: ./pki-init.sh --replace-ca"
        fi
    else
        mark fail "no CA at $PKI_ROOT" "./pki-init.sh --dry-run, then ./pki-init.sh"
    fi

    printf '\n%sCERTIFICATES%s\n' "$C_HEAD" "$C_RESET"
    local h crt n=0
    for h in $HOSTS; do
        crt=$(pki_host_cert "$h")
        if [ -r "$crt" ]; then
            mark ok "$(pki_host_fqdn "$h") ($(pki_cert_days "$crt")d)"; n=$((n+1))
        else
            mark warn "$(pki_host_fqdn "$h") not issued yet" "./renew-certs.sh --force"
        fi
    done

    printf '\n%sHOSTS%s\n' "$C_HEAD" "$C_RESET"
    for h in $HOSTS; do
        case "$(pki_ssh_probe "$h")" in
            ok)
                if pki_ssh_sudo "$h" true >/dev/null 2>&1; then
                    mark ok "$h ($(pki_host_addr "$h")) ssh + root"
                else
                    mark fail "$h ssh works but cannot get root" \
                        "give $SSH_USER passwordless sudo, or set SUDO_PASS in pki.conf"
                fi ;;
            auth)
                mark fail "$h ($(pki_host_addr "$h")) ssh auth refused for $SSH_USER" \
                    "ssh-copy-id $SSH_USER@$(pki_host_addr "$h")  - or set SSH_USER/SSH_KEY in pki.conf" ;;
            closed)
                mark fail "$h ($(pki_host_addr "$h")) port $SSH_PORT closed" "is the host up? check SSH_PORT" ;;
            hostkey)
                mark fail "$h host key changed" "ssh-keygen -R $(pki_host_addr "$h")" ;;
            timeout)
                mark fail "$h ($(pki_host_addr "$h")) timed out" "check routing/firewall" ;;
            *)
                mark fail "$h ssh failed" "try: ssh $SSH_USER@$(pki_host_addr "$h")" ;;
        esac
    done

    printf '\n%s%s ok, %s warn, %s fail%s\n' "$C_BOLD" "$ok" "$warn" "$bad" "$C_RESET"
    if [ "$bad" -gt 0 ]; then
        printf '%sfix the FAIL items before running a cutover%s\n' "$C_ERR" "$C_RESET"
        return 1
    fi
    printf '%sready%s\n' "$C_OK" "$C_RESET"
}

# Run a command, keep its output, and show it when it fails. Swallowing stderr
# on a step that touches hardware turns every failure into a guess.
pki_try() {  # description command...
    local desc="$1"; shift
    local out rc
    out=$("$@" 2>&1); rc=$?
    if [ $rc -ne 0 ]; then
        pki_err "$desc failed (exit $rc)"
        [ -n "$out" ] && printf '%s\n' "$out" | sed 's/^/       | /' >&2
        return $rc
    fi
    [ -n "$out" ] && printf '%s\n' "$out" | sed 's/^/       | /'
    return 0
}

# Run a command with its output going straight to the terminal, so prompts are
# visible. pki_try captures output, which is right for silent commands and
# wrong for anything interactive: a captured prompt looks like a hang.
pki_run_tty() {
    local desc="$1"; shift
    "$@" && return 0
    local rc=$?
    pki_err "$desc failed (exit $rc) - see the output above"
    return $rc
}

# ykman renamed the certificate subcommands between 4.x and 5.x. Detect once:
# blind fallback would re-prompt for the management key on every attempt.
pki_yk_cert_api() {
    if [ -z "${PKI_YK_CERT_API:-}" ]; then
        if timeout 20 ykman piv certificates --help >/dev/null 2>&1; then
            PKI_YK_CERT_API=new
        else
            PKI_YK_CERT_API=old
        fi
    fi
    printf '%s' "$PKI_YK_CERT_API"
}

pki_yk_mgmt_args() {
    YK_MGMT=()
    [ -n "${YK_MGMT_KEY:-}" ] && YK_MGMT=(--management-key "$YK_MGMT_KEY")
}

# 0 if the slot holds a readable certificate (which is what makes a PKCS#11
# module expose the slot's private key).
pki_yk_slot_has_cert() {
    local tmp rc=1
    tmp=$(mktemp)
    pki_yk_export_cert "${1:-$YUBIKEY_SLOT}" "$tmp" 2>/dev/null \
        && [ -s "$tmp" ] && openssl x509 -in "$tmp" -noout >/dev/null 2>&1 && rc=0
    rm -f "$tmp"
    return $rc
}

# An explicit config beats relying on the system openssl.cnf defaults or on
# -addext: both vary by distro and version, and a root CA that silently comes
# out without basicConstraints is useless and hard to notice.
pki_root_ca_cnf() {  # outfile subject
    cat > "$1" <<EOX
[req]
distinguished_name = dn
prompt             = no
x509_extensions    = v3_ca
[dn]
$(printf '%s' "$2" | sed 's#^/##; s#/#\n#g' | sed 's/ *= */ = /')
[v3_ca]
basicConstraints     = critical,CA:TRUE
keyUsage             = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOX
}

# 0 if the certificate carries basicConstraints CA:TRUE
pki_cert_is_ca() {
    openssl x509 -in "$1" -noout -text 2>/dev/null | grep -q 'CA:TRUE'
}

# ------------------------------------------------- PKCS#11 key discovery ----
# OpenSC labels PIV slots "PIV AUTH key" (9a), "SIGN key" (9c), "KEY MAN key"
# (9d), "CARD AUTH key" (9e), but labels vary by module and version. Getting
# the URI wrong only shows up at signing time, after the key already exists,
# so resolve it explicitly instead of hoping the default matches.

pki_pkcs11_slot_id() {  # PIV slot -> PKCS#11 id
    case "$1" in 9a) printf '01' ;; 9c) printf '02' ;; 9d) printf '03' ;; 9e) printf '04' ;; *) printf '02' ;; esac
}

# Ask for the PIV PIN once and keep it for the rest of the run. Never stored,
# never written to pki.conf - it lives only in this process's environment.
# The length is checked here because libp11 reports a bad length as an opaque
# "Invalid PIN length" after the prompt, and because every attempt that
# reaches the card costs one of three tries before the key is blocked.
pki_piv_pin_prompt() {
    [ -n "${PKI_PIV_PIN:-}" ] && return 0
    pki_tty_required "PIN entry" || return 1
    local pin tries
    tries=$(timeout 15 ykman piv info 2>/dev/null | sed -n 's/.*PIN tries remaining: *//p' | head -1)
    case "${tries%%/*}" in
        0) pki_err "the PIV PIN is blocked - unblock it first:"
           pki_err "    ./pki-manager.sh --run yk-unblock-pin"
           return 1 ;;
        1) pki_warn "only ONE PIN attempt remains - a wrong entry blocks the key" ;;
        '') ;;
        *) pki_info "PIV PIN tries remaining: $tries" ;;
    esac
    printf '%sPIV PIN (6-8 characters, hidden): %s' "$C_BOLD" "$C_RESET" >&2
    read -rs pin; printf '\n' >&2
    case ${#pin} in
        6|7|8) ;;
        0) pki_err "no PIN entered"; return 1 ;;
        *) pki_err "a PIV PIN is 6-8 characters, you entered ${#pin} - not sent to the key"
           return 1 ;;
    esac
    PKI_PIV_PIN="$pin"; export PKI_PIV_PIN
    pki_pin_file_init || { pki_err "could not stage the PIN file"; return 1; }
}

# PIV slot 9C is the Digital Signature key, and PIV requires a PIN check
# immediately before every signature. OpenSC marks the key
# CKA_ALWAYS_AUTHENTICATE, so libp11 performs a second, context-specific login
# that -passin never reaches - it prompts again and fails with "Invalid PIN
# length" when nothing answers. RFC 7512 pin-source satisfies both logins, and
# a file keeps the PIN out of the process command line, unlike pin-value.
# Must be called in the parent shell: creating it inside $( ) would leave the
# path in a subshell, leaking a new file per call and defeating cleanup.
pki_pin_file_init() {
    [ -n "${PKI_PIV_PIN:-}" ] || return 1
    [ -n "${PKI_PIN_FILE:-}" ] && [ -s "$PKI_PIN_FILE" ] && return 0
    PKI_PIN_FILE=$(mktemp) || return 1
    chmod 600 "$PKI_PIN_FILE"
    printf '%s' "$PKI_PIV_PIN" > "$PKI_PIN_FILE"
    export PKI_PIN_FILE
}

pki_pin_file_cleanup() {
    [ -n "${PKI_PIN_FILE:-}" ] && rm -f "$PKI_PIN_FILE"
    PKI_PIN_FILE=""
    return 0
}

# base URI -> URI carrying the PIN, for the always-authenticate login
pki_pkcs11_pin_uri() {   # read-only: safe to call inside $( )
    local uri="$1"
    { [ -n "${PKI_PIN_FILE:-}" ] && [ -s "$PKI_PIN_FILE" ]; } \
        || { printf '%s' "$uri"; return 0; }
    case "$uri" in
        *\?*) printf '%s&pin-source=file:%s' "$uri" "$PKI_PIN_FILE" ;;
        *)    printf '%s?pin-source=file:%s' "$uri" "$PKI_PIN_FILE" ;;
    esac
}

# Same, using pin-value. Only as a fallback for libp11 builds that ignore
# pin-source: this form is visible in ps, so it is never the first choice.
pki_pkcs11_pinvalue_uri() {
    local uri="$1"
    [ -n "${PKI_PIV_PIN:-}" ] || { printf '%s' "$uri"; return 0; }
    case "$uri" in
        *\?*) printf '%s&pin-value=%s' "$uri" "$PKI_PIV_PIN" ;;
        *)    printf '%s?pin-value=%s' "$uri" "$PKI_PIV_PIN" ;;
    esac
}

pki_pkcs11_pass_args() {
    PK11_PASS=()
    [ -n "${PKI_PIV_PIN:-}" ] && PK11_PASS=(-passin env:PKI_PIV_PIN)
}

# 0 = key loads, 1 = not found, 2 = PIN problem (caller must stop immediately)
pki_pkcs11_key_works() {
    local uri="$1" out rc
    pki_pkcs11_pass_args
    case "$PKCS11_MODE" in
        engine)
            out=$(openssl pkey -engine pkcs11 -inform engine -in "$uri" \
                  "${PK11_PASS[@]}" -pubout -noout 2>&1); rc=$? ;;
        provider)
            out=$(openssl pkey -provider pkcs11 -provider default -in "$uri" \
                  "${PK11_PASS[@]}" -pubout -noout 2>&1); rc=$? ;;
        *) return 1 ;;
    esac
    PKI_PKCS11_LAST_ERR="$out"
    [ $rc -eq 0 ] && return 0
    case "$out" in
        *"Invalid PIN"*|*CKR_PIN*|*"PIN incorrect"*|*"PIN locked"*|*"pin locked"*) return 2 ;;
    esac
    return 1
}

# Echoes a working URI for the slot, or nothing. Sets YK_ROOT_KEY_URI on success.
pki_pkcs11_resolve_key() {
    local slot="${1:-$YUBIKEY_SLOT}" id cand rc
    id=$(pki_pkcs11_slot_id "$slot")

    for cand in "$YK_ROOT_KEY_URI" \
                "pkcs11:id=%${id};type=private" \
                "pkcs11:object=SIGN%20key;type=private" \
                "pkcs11:object=PIV%20AUTH%20key;type=private" \
                "pkcs11:object=KEY%20MAN%20key;type=private" \
                "pkcs11:slot-id=0;id=%${id};type=private"; do
        [ -n "$cand" ] || continue
        pki_pkcs11_key_works "$cand"; rc=$?
        case $rc in
            0)  YK_ROOT_KEY_URI="$cand"; printf '%s' "$cand"; return 0 ;;
            2)  # a wrong PIN costs one of three tries - stop before the rest
                pki_err "the PIV PIN was rejected - stopping so no further attempts are used" >&2
                [ -n "${PKI_PKCS11_LAST_ERR:-}" ] \
                    && printf '%s\n' "$PKI_PKCS11_LAST_ERR" | sed 's/^/       | /' >&2
                pki_err "check remaining tries:  ./pki-manager.sh --run yk-retries" >&2
                return 2 ;;
        esac
    done
    return 1
}

# Read-only: show what the module exposes and whether the configured URI works.
act_yk_pkcs11() {
    pki_pkcs11_detect || { pki_pkcs11_hint; return 1; }
    pki_info "== PKCS#11"
    pki_info "   mode:   $PKCS11_MODE"
    pki_info "   module: $PKCS11_MODULE"
    pki_info "   uri:    $YK_ROOT_KEY_URI"
    printf '\n'

    if command -v pkcs11-tool >/dev/null 2>&1 && [ -r "$PKCS11_MODULE" ]; then
        pki_info "-- objects on the token"
        timeout 30 pkcs11-tool --module "$PKCS11_MODULE" -O 2>&1 \
            | grep -iE 'object|label|ID:|Usage|type' | sed 's/^/   /' | head -40
        printf '\n'
    else
        pki_warn "pkcs11-tool not installed (apt install opensc) - cannot list objects"
    fi

    pki_info "-- can openssl load a private key?"
    local found
    if found=$(pki_pkcs11_resolve_key "$YUBIKEY_SLOT"); then
        if [ "$found" = "${YK_ROOT_KEY_URI_ORIG:-$found}" ]; then :; fi
        pki_ok "usable key URI: $found"
        [ "$found" = "$YK_ROOT_KEY_URI" ] || pki_warn "differs from pki.conf - set YK_ROOT_KEY_URI=\"$found\""
    else
        pki_err "no private key reachable for slot $YUBIKEY_SLOT"
        pki_err "if the slot is empty this is expected until pki-init.sh generates the key"
        return 1
    fi
}
