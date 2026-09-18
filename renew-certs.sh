#!/usr/bin/env bash
# renew-certs.sh - issue and renew pamperins.lan service certificates.
#
# Source of truth for renewal logic. Signs with the intermediate CA on disk,
# so it needs no YubiKey, no PIN and no touch: safe to run from cron.
# Creating or replacing the CA itself is pki-init.sh's job.
set -uo pipefail

SELF_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [ -r "$SELF_DIR/lib/pki-lib.sh" ]; then
    . "$SELF_DIR/lib/pki-lib.sh"
elif [ -r "$SELF_DIR/../lib/pki-lib.sh" ]; then
    . "$SELF_DIR/../lib/pki-lib.sh"
else
    echo "ERR cannot find lib/pki-lib.sh next to renew-certs.sh" >&2
    exit 1
fi

usage() {
    cat <<EOF
usage: renew-certs.sh [options] [host...]

Renews any cert due within RENEW_BEFORE_DAYS (${RENEW_BEFORE_DAYS:-30}).
With no hosts named, every host in HOSTS is considered.

  -f, --force         renew regardless of remaining lifetime
  -k, --rotate-keys   generate a fresh private key (default: reuse the key)
  -d, --days N        validity in days (default: \$LEAF_DAYS)
  -l, --list          report what is due, change nothing
  -n, --dry-run       same as --list
      --no-log        do not write a log file
  -h, --help          this
EOF
}

FORCE=0 ROTATE=0 DAYS="" LIST=0 SELFLOG=1 TARGETS=()
while [ $# -gt 0 ]; do
    case "$1" in
        -f|--force)       FORCE=1; shift ;;
        -k|--rotate-keys) ROTATE=1; shift ;;
        -d|--days)        DAYS="${2:-}"; shift 2 ;;
        -l|--list|-n|--dry-run) LIST=1; shift ;;
        --no-log)         SELFLOG=0; shift ;;
        -h|--help)        pki_load_conf; usage; exit 0 ;;
        -*)               echo "ERR unknown option: $1" >&2; exit 2 ;;
        *)                TARGETS+=("$1"); shift ;;
    esac
done

pki_load_conf
DAYS="${DAYS:-$LEAF_DAYS}"
case "$DAYS" in ''|*[!0-9]*) pki_err "--days needs a number"; exit 2 ;; esac

[ ${#TARGETS[@]} -eq 0 ] && read -r -a TARGETS <<<"$HOSTS"
for h in "${TARGETS[@]}"; do
    pki_host_valid "$h" || { pki_err "unknown host: $h (have: $HOSTS)"; exit 2; }
done

# The CA has to exist before anything can be signed.
if [ ! -r "$INT_CA_CRT" ] || [ ! -r "$INT_CA_KEY" ]; then
    pki_err "no intermediate CA at $INT_CA_DIR"
    pki_err "run ./pki-init.sh first to create the CA hierarchy"
    exit 1
fi
if [ ! -r "$ROOT_CA_CRT" ]; then
    pki_err "no root CA cert at $ROOT_CA_CRT - run ./pki-init.sh"
    exit 1
fi

# Refuse to issue from a CA that is itself expiring: the leaf would outlive it.
int_days=$(pki_cert_days "$INT_CA_CRT")
if [ -n "$int_days" ] && [ "$int_days" -le 0 ]; then
    pki_err "intermediate CA expired ${int_days#-} days ago - renew the CA before the leaves"
    exit 1
fi
if [ -n "$int_days" ] && [ "$int_days" -lt "$DAYS" ]; then
    pki_warn "intermediate expires in ${int_days}d, shorter than the requested ${DAYS}d"
    pki_warn "capping leaf validity at ${int_days}d"
    DAYS="$int_days"
fi

if [ "$SELFLOG" = 1 ] && [ "$LIST" = 0 ]; then
    mkdir -p "$LOG_DIR"
    LOGFILE="$LOG_DIR/renew-$(date +%Y%m%d-%H%M%S).log"
    exec > >(tee -a "$LOGFILE") 2>&1
fi

printf '== renew-certs %s  threshold %sd  validity %sd%s\n' \
    "$(date '+%Y-%m-%d %H:%M:%S')" "$RENEW_BEFORE_DAYS" "$DAYS" \
    "$([ "$FORCE" = 1 ] && printf ' (forced)')"

due=0 done_ok=0 failed=0 skipped=0
for h in "${TARGETS[@]}"; do
    fqdn=$(pki_host_fqdn "$h")
    crt=$(pki_host_cert "$h")
    if [ -r "$crt" ]; then
        days=$(pki_cert_days "$crt")
    else
        days=""
    fi

    if [ -z "$days" ]; then
        reason="no certificate yet"
    elif [ "$FORCE" = 1 ]; then
        reason="forced (${days}d left)"
    elif [ "$days" -le "$RENEW_BEFORE_DAYS" ]; then
        reason="${days}d left"
    else
        printf '   skip  %-26s %sd left\n' "$fqdn" "$days"
        skipped=$((skipped+1))
        continue
    fi

    due=$((due+1))
    if [ "$LIST" = 1 ]; then
        printf '   due   %-26s %s\n' "$fqdn" "$reason"
        continue
    fi

    printf '\n-- %s (%s)\n' "$fqdn" "$reason"
    if pki_issue_cert "$h" "$DAYS" "$ROTATE"; then
        done_ok=$((done_ok+1))
    else
        failed=$((failed+1))
    fi
done

printf '\n== due %s  renewed %s  failed %s  skipped %s\n' "$due" "$done_ok" "$failed" "$skipped"
[ "$LIST" = 1 ] && exit 0
if [ "$done_ok" -gt 0 ]; then
    printf 'Certificates changed - deploy them:  ./pki-manager.sh --run deploy-all\n'
fi
[ "$failed" -gt 0 ] && exit 1
exit 0
