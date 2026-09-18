#!/usr/bin/env bash
# pki-init.sh - create the pamperins.lan CA hierarchy from nothing.
#
#   Root CA     : key generated ON the YubiKey (PIV slot 9c), never extractable
#   Intermediate: key on disk, signed by the YubiKey root
#
# Run once. Routine issuance and renewal afterwards is renew-certs.sh, which
# uses the intermediate only and needs no PIN and no touch.
set -uo pipefail

SELF_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
. "$SELF_DIR/lib/pki-lib.sh"

DRY=0 FORCE_SLOT=0 FORCE_CA=0
usage() {
    cat <<EOF
usage: pki-init.sh [options]

  -n, --dry-run        print every command, change nothing
      --replace-ca     overwrite an existing intermediate CA on disk
      --replace-slot   overwrite a key already in YubiKey slot $YUBIKEY_SLOT (DESTRUCTIVE)
  -h, --help           this

Requires: ykman, openssl with PKCS#11 (libengine-pkcs11-openssl or pkcs11-provider),
and the YubiKey plugged in. You will be prompted for the PIV PIN and management
key, and asked to touch the key.
EOF
}
while [ $# -gt 0 ]; do
    case "$1" in
        -n|--dry-run)   DRY=1; shift ;;
        --replace-ca)   FORCE_CA=1; shift ;;
        --replace-slot) FORCE_SLOT=1; shift ;;
        -h|--help)      pki_load_conf; usage; exit 0 ;;
        *) echo "ERR unknown option: $1" >&2; exit 2 ;;
    esac
done

pki_load_conf

run() {  # echo in dry-run, execute otherwise
    if [ "$DRY" = 1 ]; then printf '   $ %s\n' "$*"; return 0; fi
    "$@"
}

step() { printf '\n%s== %s%s\n' "$C_HEAD" "$*" "$C_RESET"; }

# ----------------------------------------------------------- 0 preflight ----
step "0/5 preflight"
rc=0
for t in openssl ykman; do
    if command -v "$t" >/dev/null 2>&1; then
        pki_ok "$t $(command -v "$t")"
    else
        pki_err "$t not installed"; rc=1
    fi
done
if [ "$rc" != 0 ]; then
    if [ "$DRY" = 1 ]; then
        pki_warn "tools missing - dry run continues so you can review the plan"
    else
        pki_err "install the missing tools first"; exit 1
    fi
fi

if pki_pkcs11_detect; then
    pki_ok "openssl PKCS#11 via $PKCS11_MODE"
else
    pki_pkcs11_hint; [ "$DRY" = 1 ] || exit 1
    PKCS11_MODE=engine
fi
pki_pkcs11_key_args; pki_pkcs11_cakey_args

if [ "$DRY" = 0 ] && ! timeout 15 ykman piv info >/dev/null 2>&1; then
    pki_err "no YubiKey detected - plug it in"
    exit 1
fi

# refuse to clobber an existing root key: it would orphan every cert under it
if [ "$DRY" = 0 ] && timeout 15 ykman piv info 2>/dev/null | grep -q "^Slot ${YUBIKEY_SLOT}"; then
    if [ "$FORCE_SLOT" = 1 ]; then
        pki_warn "slot $YUBIKEY_SLOT is occupied and --replace-slot was given: it will be OVERWRITTEN"
        printf '%stype REPLACE to continue: %s' "$C_WARN" "$C_RESET"
        read -r ans; [ "$ans" = REPLACE ] || { pki_info "aborted"; exit 1; }
    else
        pki_err "slot $YUBIKEY_SLOT already holds a key - refusing to overwrite"
        pki_err "inspect it:  ./pki-manager.sh --run yk-slot $YUBIKEY_SLOT"
        pki_err "to replace anyway (orphans every cert under the old root): --replace-slot"
        exit 1
    fi
fi

if [ -s "$INT_CA_KEY" ] && [ "$FORCE_CA" = 0 ]; then
    pki_err "intermediate CA already exists: $INT_CA_KEY"
    pki_err "to replace it: --replace-ca"
    exit 1
fi

# -------------------------------------------------------------- 1 layout ----
step "1/5 directory layout under $PKI_ROOT"
for d in "$ROOT_CA_DIR" "$INT_CA_DIR" "$CERT_DIR" "$LOG_DIR"; do
    run mkdir -p "$d" && pki_info "   $d"
done
[ "$DRY" = 1 ] || chmod 700 "$INT_CA_DIR" "$CERT_DIR"

# ------------------------------------------------------- 2 root CA on key ----
step "2/5 root CA keypair on YubiKey slot $YUBIKEY_SLOT"
pki_info "   algorithm $YK_KEY_ALGO, touch policy ${YK_TOUCH_POLICY:-ALWAYS}"
pki_warn "the private key is created on the device and can never be read out"
PUB="$ROOT_CA_DIR/$ROOT_CA_NAME.pub.pem"

if [ "$DRY" = 1 ]; then
    run ykman piv keys generate --algorithm "$YK_KEY_ALGO" \
        --pin-policy "${YK_PIN_POLICY:-ONCE}" --touch-policy "${YK_TOUCH_POLICY:-ALWAYS}" \
        "$YUBIKEY_SLOT" "$PUB"
else
    if ! timeout 180 ykman piv keys generate --algorithm "$YK_KEY_ALGO" \
            --pin-policy "${YK_PIN_POLICY:-ONCE}" --touch-policy "${YK_TOUCH_POLICY:-ALWAYS}" \
            "$YUBIKEY_SLOT" "$PUB" 2>&1 \
       && ! timeout 180 ykman piv generate-key -a "$YK_KEY_ALGO" \
            --pin-policy "${YK_PIN_POLICY:-ONCE}" --touch-policy "${YK_TOUCH_POLICY:-ALWAYS}" \
            "$YUBIKEY_SLOT" "$PUB" 2>&1; then
        pki_err "key generation failed on slot $YUBIKEY_SLOT"
        exit 1
    fi
    pki_ok "keypair generated, public key: $PUB"
fi

# A PKCS#11 module only exposes a PIV private key once the slot holds a
# certificate, so plant a throwaway one before asking openssl to self-sign.
step "3/5 self-signed root certificate (proper CA extensions)"
pki_info "   bootstrap cert first, so PKCS#11 can see the key"
if [ "$DRY" = 1 ]; then
    run ykman piv certificates generate --subject "$ROOT_CA_SUBJECT" --valid-days 1 "$YUBIKEY_SLOT" "$PUB"
else
    timeout 180 ykman piv certificates generate --subject "$ROOT_CA_SUBJECT" \
        --valid-days 1 "$YUBIKEY_SLOT" "$PUB" >/dev/null 2>&1 \
    || timeout 180 ykman piv generate-certificate -s "$ROOT_CA_SUBJECT" \
        -d 1 "$YUBIKEY_SLOT" "$PUB" >/dev/null 2>&1 \
    || { pki_err "could not write the bootstrap certificate"; exit 1; }
    pki_ok "bootstrap certificate in slot $YUBIKEY_SLOT"
fi

pki_info "   signing the real root certificate with the on-device key (touch required)"
if [ "$DRY" = 1 ]; then
    run openssl req -x509 -new -sha256 "${PK11_KEY[@]}" -key "$YK_ROOT_KEY_URI" \
        -subj "$ROOT_CA_SUBJECT" -days "$ROOT_CA_DAYS" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -addext "subjectKeyIdentifier=hash" -out "$ROOT_CA_CRT"
else
    if ! openssl req -x509 -new -sha256 "${PK11_KEY[@]}" -key "$YK_ROOT_KEY_URI" \
            -subj "$ROOT_CA_SUBJECT" -days "$ROOT_CA_DAYS" \
            -addext "basicConstraints=critical,CA:TRUE" \
            -addext "keyUsage=critical,keyCertSign,cRLSign" \
            -addext "subjectKeyIdentifier=hash" \
            -out "$ROOT_CA_CRT" 2>&1; then
        pki_err "self-signing failed - check YK_ROOT_KEY_URI ($YK_ROOT_KEY_URI) and PKCS11_MODULE"
        exit 1
    fi
    chmod 644 "$ROOT_CA_CRT"
    if ! openssl x509 -in "$ROOT_CA_CRT" -noout -text 2>/dev/null | grep -q 'CA:TRUE'; then
        pki_err "root certificate lacks basicConstraints CA:TRUE - refusing to continue"
        exit 1
    fi
    pki_ok "root CA: $ROOT_CA_CRT ($(pki_cert_days "$ROOT_CA_CRT")d)"
    # store the real cert on the key, replacing the bootstrap one
    pki_yk_import_cert "$YUBIKEY_SLOT" "$ROOT_CA_CRT" >/dev/null 2>&1 \
        && pki_ok "root certificate written to slot $YUBIKEY_SLOT" \
        || pki_warn "could not store the cert on the key (harmless: $ROOT_CA_CRT is authoritative)"
fi

# --------------------------------------------------- 4 intermediate CA ------
step "4/5 intermediate CA (key on disk, signed by the YubiKey root)"
if [ "$DRY" = 1 ]; then
    run openssl genrsa -out "$INT_CA_KEY" 2048
    run openssl req -new -key "$INT_CA_KEY" -subj "$INT_CA_SUBJECT" -out "$INT_CA_CSR"
    run openssl x509 -req -sha256 "${PK11_CAKEY[@]}" -in "$INT_CA_CSR" \
        -CA "$ROOT_CA_CRT" -CAkey "$YK_ROOT_KEY_URI" -CAcreateserial \
        -days "$INT_CA_DAYS" -extfile '<generated>' -out "$INT_CA_CRT"
else
    pki_genkey "$INT_CA_KEY" || exit 1
    pki_ok "intermediate key: $INT_CA_KEY (mode 600)"
    if ! openssl req -new -key "$INT_CA_KEY" -subj "$INT_CA_SUBJECT" -out "$INT_CA_CSR" 2>/dev/null; then
        pki_err "intermediate CSR failed"; exit 1
    fi
    EXT=$(mktemp); pki_int_extfile "$EXT"
    pki_info "   signing with the YubiKey root (PIN + touch)"
    if ! openssl x509 -req -sha256 "${PK11_CAKEY[@]}" -in "$INT_CA_CSR" \
            -CA "$ROOT_CA_CRT" -CAkey "$YK_ROOT_KEY_URI" \
            -CAcreateserial -days "$INT_CA_DAYS" -extfile "$EXT" \
            -out "$INT_CA_CRT" 2>&1; then
        rm -f "$EXT"; pki_err "intermediate signing failed"; exit 1
    fi
    rm -f "$EXT"; chmod 644 "$INT_CA_CRT"
    if openssl verify -CAfile "$ROOT_CA_CRT" "$INT_CA_CRT" >/dev/null 2>&1; then
        pki_ok "intermediate CA: $INT_CA_CRT ($(pki_cert_days "$INT_CA_CRT")d), verifies against the root"
    else
        pki_err "intermediate does not verify against the root"; exit 1
    fi
fi

# --------------------------------------------------------------- 5 done ----
step "5/5 done"
[ "$DRY" = 1 ] && { pki_info "dry run - nothing was changed"; exit 0; }

printf '\n'
pki_ok "CA hierarchy created under $PKI_ROOT"
openssl x509 -in "$ROOT_CA_CRT" -noout -subject -dates -fingerprint -sha256 2>/dev/null | sed 's/^/   /'

cat <<EOF

${C_HEAD}NEXT - order matters, your servers are live${C_RESET}

  1. Issue the service certificates (no PIN needed):
       ./renew-certs.sh --force

  2. Trust the new root EVERYWHERE before swapping any cert.
     Existing certs keep working; this only adds an anchor:
       ./pki-manager.sh --run trust-push-all

  3. Confirm the new root is trusted on each host, then swap certs:
       ./pki-manager.sh --run deploy-all

  4. Verify, and fix ldap.conf to point at the new root:
       ./pki-manager.sh --run ldap-fix-all
       ./pki-manager.sh --run verify-tls

  Doing 3 before 2 breaks LDAPS and Samba. The dashboard shows the
  state after every step: ./pki-manager.sh
EOF
