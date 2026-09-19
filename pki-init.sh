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

DRY=0 FORCE_SLOT=0 FORCE_CA=0 REUSE_SLOT=0 INT_ONLY=0 SKIP_SLOT_IMPORT=0
usage() {
    cat <<EOF
usage: pki-init.sh [options]

  -n, --dry-run        print every command, change nothing
      --replace-ca     overwrite an existing intermediate CA on disk
      --intermediate-only
                       root CA already exists: create only the intermediate
                       (use this to resume after step 4 failed)
      --skip-slot-import
                       do not store the root cert on the key (it is optional;
                       do it later with: pki-manager.sh --run yk-import-root)
      --reuse-slot     keep the key already in slot $YUBIKEY_SLOT and carry on
                       (use this to retry after a failure past key generation)
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
        --intermediate-only) INT_ONLY=1; FORCE_CA=1; shift ;;
        --skip-slot-import) SKIP_SLOT_IMPORT=1; shift ;;
        --reuse-slot)   REUSE_SLOT=1; shift ;;
        --replace-slot) FORCE_SLOT=1; shift ;;
        -h|--help)      pki_load_conf; usage; exit 0 ;;
        *) echo "ERR unknown option: $1" >&2; exit 2 ;;
    esac
done

pki_load_conf
trap 'pki_pin_file_cleanup' EXIT INT TERM

run() {  # echo in dry-run, execute otherwise
    if [ "$DRY" = 1 ]; then
        # quote every argument: the PKCS#11 URI contains ';' and subjects
        # contain spaces, so unquoted output is not safe to copy and paste
        local a out=""
        for a in "$@"; do out="$out $(printf '%q' "$a")"; done
        printf '   $%s\n' "$out"
        return 0
    fi
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

if [ "$DRY" = 0 ]; then
    YKOUT=$(timeout 15 ykman piv info 2>&1); YKRC=$?
    if [ $YKRC -ne 0 ]; then
        pki_err "cannot talk to the YubiKey (exit $YKRC)"
        [ -n "$YKOUT" ] && printf '%s\n' "$YKOUT" | sed 's/^/       | /' >&2
        case "$YKOUT" in
            *[Pp]"C/SC"*|*pcscd*|*[Ss]mart[Cc]ard*|*"Failed to connect"*)
                pki_err "this usually means the smartcard daemon is not running:"
                pki_err "    sudo systemctl enable --now pcscd" ;;
            *[Pp]ermission*|*[Aa]ccess*[Dd]enied*)
                pki_err "permission problem reaching the device - check udev rules, or try sudo" ;;
            *) pki_err "is the key plugged in?" ;;
        esac
        exit 1
    fi
fi

# refuse to clobber an existing root key: it would orphan every cert under it
if [ "$DRY" = 0 ] && [ "$INT_ONLY" = 0 ] && pki_yk_slot_occupied "$YUBIKEY_SLOT"; then
    if [ "$REUSE_SLOT" = 1 ]; then
        pki_info "slot $YUBIKEY_SLOT already holds a key - reusing it (--reuse-slot)"
    elif [ "$FORCE_SLOT" = 1 ]; then
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

if [ "$INT_ONLY" = 1 ]; then
    step "resume: intermediate only"
    if [ ! -r "$ROOT_CA_CRT" ]; then
        pki_err "no root CA at $ROOT_CA_CRT - cannot create an intermediate without it"
        exit 1
    fi
    if ! pki_cert_is_ca "$ROOT_CA_CRT"; then
        pki_err "$ROOT_CA_CRT is not a CA certificate (no basicConstraints CA:TRUE)"
        pki_err "this is the throwaway bootstrap cert: the root self-sign never completed"
        pki_err ""
        pki_err "the KEY in slot $YUBIKEY_SLOT is fine - only the certificate is wrong."
        pki_err "re-sign it without regenerating the key:"
        pki_err "    ./pki-init.sh --reuse-slot"
        exit 1
    fi
    pki_ok "root CA present: $(openssl x509 -in "$ROOT_CA_CRT" -noout -subject | sed 's/subject=*//')"
    pki_ok "valid $(pki_cert_days "$ROOT_CA_CRT")d, CA:TRUE"
    if [ "$DRY" = 0 ]; then
        pki_piv_pin_prompt || exit 1
        if RESOLVED=$(pki_pkcs11_resolve_key "$YUBIKEY_SLOT"); then
            YK_ROOT_KEY_URI="$RESOLVED"
            pki_ok "PKCS#11 key URI: $RESOLVED"
        else
            pki_err "no PKCS#11 private key for slot $YUBIKEY_SLOT"
            pki_err "diagnose: ./pki-manager.sh --run yk-pkcs11"
            exit 1
        fi
    fi
fi

# -------------------------------------------------------------- 1 layout ----
[ "$INT_ONLY" = 1 ] || step "1/5 directory layout under $PKI_ROOT"
for d in "$ROOT_CA_DIR" "$INT_CA_DIR" "$CERT_DIR" "$LOG_DIR"; do
    run mkdir -p "$d" && pki_info "   $d"
done
[ "$DRY" = 1 ] || chmod 700 "$INT_CA_DIR" "$CERT_DIR"

# ------------------------------------------------------- 2 root CA on key ----
if [ "$INT_ONLY" = 0 ]; then
step "2/5 root CA keypair on YubiKey slot $YUBIKEY_SLOT"
pki_info "   algorithm $YK_KEY_ALGO, touch policy ${YK_TOUCH_POLICY:-ALWAYS}"
pki_warn "the private key is created on the device and can never be read out"
PUB="$ROOT_CA_DIR/$ROOT_CA_NAME.pub.pem"

if [ "$REUSE_SLOT" = 1 ] && [ "$DRY" = 0 ]; then
    pki_info "   skipping generation, using the existing slot key"
elif [ "$DRY" = 1 ]; then
    run ykman piv keys generate --algorithm "$YK_KEY_ALGO" \
        --pin-policy "${YK_PIN_POLICY:-ONCE}" --touch-policy "${YK_TOUCH_POLICY:-ALWAYS}" \
        "$YUBIKEY_SLOT" "$PUB"
else
    if ! timeout "${PIV_TIMEOUT:-300}" ykman piv keys generate --algorithm "$YK_KEY_ALGO" \
            --pin-policy "${YK_PIN_POLICY:-ONCE}" --touch-policy "${YK_TOUCH_POLICY:-ALWAYS}" \
            "$YUBIKEY_SLOT" "$PUB" 2>&1 \
       && ! timeout "${PIV_TIMEOUT:-300}" ykman piv generate-key -a "$YK_KEY_ALGO" \
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
# The bootstrap certificate exists only so a PKCS#11 module will expose the
# slot's private key. If the slot already holds one, that is already true and
# there is nothing to plant.
if [ "$DRY" = 1 ]; then
    pki_info "   bootstrap cert first, so PKCS#11 can see the key"
    run ykman piv certificates generate --subject "$ROOT_CA_SUBJECT" --valid-days 1 "$YUBIKEY_SLOT" "$PUB"
elif pki_yk_slot_has_cert "$YUBIKEY_SLOT"; then
    pki_info "   slot already holds a certificate - PKCS#11 can see the key, no bootstrap needed"
else
    pki_info "   bootstrap cert first, so PKCS#11 can see the key"
    # Only the key-generation step writes the public key file, so recover it
    # from the slot when we are reusing a key generated by an earlier run.
    if [ ! -s "$PUB" ]; then
        pki_info "   no public key file - recovering it from slot $YUBIKEY_SLOT"
        RECOVER=$(mktemp)
        if pki_yk_export_cert "$YUBIKEY_SLOT" "$RECOVER" 2>/dev/null && [ -s "$RECOVER" ]; then
            openssl x509 -in "$RECOVER" -noout -pubkey > "$PUB" 2>/dev/null
        fi
        rm -f "$RECOVER"
        if [ ! -s "$PUB" ]; then
            pki_err "no public key for slot $YUBIKEY_SLOT and none could be recovered"
            pki_err "the slot has neither a certificate nor a saved public key"
            pki_err "generate a fresh keypair: ./pki-init.sh --replace-slot"
            exit 1
        fi
    fi
    pki_warn "   $(pki_yk_mgmt_prompt_hint)"
    pki_yk_mgmt_args
    if [ "$(pki_yk_cert_api)" = new ]; then
        pki_run_tty "bootstrap certificate" timeout "${PIV_TIMEOUT:-300}" \
            ykman piv certificates generate "${YK_MGMT[@]}" \
            --subject "$ROOT_CA_SUBJECT" --valid-days 1 "$YUBIKEY_SLOT" "$PUB"
    else
        pki_run_tty "bootstrap certificate" timeout "${PIV_TIMEOUT:-300}" \
            ykman piv generate-certificate "${YK_MGMT[@]}" \
            -s "$ROOT_CA_SUBJECT" -d 1 "$YUBIKEY_SLOT" "$PUB"
    fi || { pki_err "could not write the bootstrap certificate - see the output above"; exit 1; }
    pki_warn "slot now holds a THROWAWAY certificate - not a CA, replaced in the next step"
fi

# One PIN prompt for the whole run. openssl would otherwise ask separately for
# the token PIN and the key PIN, and once more per URI probed, which is how a
# mistyped entry slips in - and every attempt that reaches the card costs one
# of three tries.
if [ "$DRY" = 0 ]; then
    pki_piv_pin_prompt || exit 1
fi

# The module only exposes the key now that the slot holds a certificate, so
# this is the first moment the URI can be checked. Doing it here means a wrong
# URI is reported before it can waste the key.
if [ "$DRY" = 0 ]; then
    if RESOLVED=$(pki_pkcs11_resolve_key "$YUBIKEY_SLOT"); then
        [ "$RESOLVED" = "$YK_ROOT_KEY_URI" ] \
            && pki_ok "PKCS#11 key URI verified: $RESOLVED" \
            || { YK_ROOT_KEY_URI="$RESOLVED"
                 pki_warn "configured URI did not resolve; using $RESOLVED"
                 pki_warn "add to pki.conf:  YK_ROOT_KEY_URI=\"$RESOLVED\"" ; }
    else
        pki_err "no PKCS#11 private key found for slot $YUBIKEY_SLOT"
        pki_err "diagnose:  ./pki-manager.sh --run yk-pkcs11"
        pki_err "then retry:  ./pki-init.sh --reuse-slot   (keeps the key just generated)"
        exit 1
    fi
fi

pki_info "   signing the real root certificate with the on-device key"
pki_info "   slot $YUBIKEY_SLOT re-checks the PIN before every signature (PIV rule for 9C)"
pki_warn "   TOUCH THE KEY when it starts blinking"
CACNF="$ROOT_CA_DIR/root-ca.cnf"
if [ "$DRY" = 1 ]; then
    run openssl req -x509 -new -sha256 "${PK11_KEY[@]}" -key "$YK_ROOT_KEY_URI" \
        -config "$CACNF" -extensions v3_ca -days "$ROOT_CA_DAYS" -out "$ROOT_CA_CRT"
else
    pki_root_ca_cnf "$CACNF" "$ROOT_CA_SUBJECT"
    pki_pkcs11_pass_args
    sign_root() {  # $1 = key URI
        openssl req -x509 -new -sha256 "${PK11_KEY[@]}" -key "$1" \
            "${PK11_PASS[@]}" -config "$CACNF" -extensions v3_ca \
            -days "$ROOT_CA_DAYS" -out "$ROOT_CA_CRT" 2>&1
    }
    SIGNED=0
    # Both pin-source spellings keep the PIN out of ps; pin-value does not,
    # so it is only reached when this libp11 build honours neither.
    if sign_root "$(pki_pkcs11_pin_uri "$YK_ROOT_KEY_URI" file)"; then
        SIGNED=1
    elif sign_root "$(pki_pkcs11_pin_uri "$YK_ROOT_KEY_URI" path)"; then
        SIGNED=1
        pki_info "   this libp11 wants pin-source without the file: prefix"
    else
        pki_warn "neither pin-source form was honoured, falling back to pin-value"
        pki_warn "the PIN is briefly visible in ps while this signs"
        sign_root "$(pki_pkcs11_pinvalue_uri "$YK_ROOT_KEY_URI")" && SIGNED=1
    fi
    if [ "$SIGNED" = 0 ]; then
        pki_err "self-signing failed - check YK_ROOT_KEY_URI ($YK_ROOT_KEY_URI) and PKCS11_MODULE"
        pki_err "PIN tries remaining: $(timeout 15 ykman piv info 2>/dev/null | sed -n 's/.*PIN tries remaining: *//p' | head -1)"
        pki_err "diagnose: ./pki-manager.sh --run yk-pkcs11"
        pki_err "retry without regenerating the key: ./pki-init.sh --reuse-slot"
        pki_err "NOTE: slot $YUBIKEY_SLOT still holds the throwaway bootstrap certificate,"
        pki_err "      which is NOT a usable CA. The root is not finished until this step is."
        exit 1
    fi
    chmod 644 "$ROOT_CA_CRT"
    if ! pki_cert_is_ca "$ROOT_CA_CRT"; then
        pki_err "root certificate came out without basicConstraints CA:TRUE"
        pki_err "it cannot sign an intermediate - refusing to continue"
        exit 1
    fi
    pki_ok "root CA: $ROOT_CA_CRT ($(pki_cert_days "$ROOT_CA_CRT")d, CA:TRUE)"

    # Replace the bootstrap cert on the key, then read back what is actually
    # there. Without this a failed import leaves the throwaway cert in place
    # and everything downstream fails much later with a confusing error.
    pki_info "   writing the root certificate to slot $YUBIKEY_SLOT"
    pki_warn "   $(pki_yk_mgmt_prompt_hint)"
    pki_warn "   then TOUCH THE KEY - it blinks without printing anything"
    pki_info "   a countdown appears below; it gives up after ${PIV_IMPORT_TIMEOUT}s and carries on"
    # Storing the certificate on the key is a convenience: the copy on disk is
    # what signs and what gets distributed, and the slot only needs *some*
    # certificate for PKCS#11 to expose the private key. So a failure here is
    # reported and stepped over rather than stopping the whole build.
    SLOT_OK=0
    if [ "$SKIP_SLOT_IMPORT" = 1 ]; then
        pki_info "   skipped (--skip-slot-import)"
    elif pki_run_tty_timed "import root certificate into slot $YUBIKEY_SLOT" \
            "$PIV_IMPORT_TIMEOUT" pki_yk_import_cert "$YUBIKEY_SLOT" "$ROOT_CA_CRT"; then
        VERIFY=$(mktemp)
        if pki_yk_export_cert "$YUBIKEY_SLOT" "$VERIFY" && pki_cert_is_ca "$VERIFY"; then
            pki_ok "slot $YUBIKEY_SLOT now holds the real root certificate (verified CA:TRUE)"
            SLOT_OK=1
        fi
        rm -f "$VERIFY"
    fi
    if [ "$SLOT_OK" = 0 ] && [ "$SKIP_SLOT_IMPORT" = 0 ]; then
        pki_warn "could not store the root certificate on the key - CONTINUING"
        pki_warn "  $ROOT_CA_CRT is authoritative and unaffected"
        pki_warn "  the slot keeps its old certificate, which still lets PKCS#11 sign"
        pki_warn "  retry later with:  ./pki-manager.sh --run yk-import-root"
    fi
fi

fi   # end of root CA creation (skipped by --intermediate-only)

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
    pki_info "   signing with the YubiKey root"
    pki_warn "   TOUCH THE KEY when it starts blinking"
    pki_pkcs11_pass_args
    sign_int() {  # $1 = CA key URI
        openssl x509 -req -sha256 "${PK11_CAKEY[@]}" -in "$INT_CA_CSR" \
            -CA "$ROOT_CA_CRT" -CAkey "$1" "${PK11_PASS[@]}" \
            -CAcreateserial -days "$INT_CA_DAYS" -extfile "$EXT" \
            -out "$INT_CA_CRT" 2>&1
    }
    INTSIGNED=0
    # Both pin-source spellings keep the PIN out of ps; pin-value does not,
    # so it is only reached when this libp11 build honours neither.
    if sign_int "$(pki_pkcs11_pin_uri "$YK_ROOT_KEY_URI" file)"; then
        INTSIGNED=1
    elif sign_int "$(pki_pkcs11_pin_uri "$YK_ROOT_KEY_URI" path)"; then
        INTSIGNED=1
        pki_info "   this libp11 wants pin-source without the file: prefix"
    else
        pki_warn "neither pin-source form was honoured, falling back to pin-value"
        pki_warn "the PIN is briefly visible in ps while this signs"
        sign_int "$(pki_pkcs11_pinvalue_uri "$YK_ROOT_KEY_URI")" && INTSIGNED=1
    fi
    if [ "$INTSIGNED" = 0 ]; then
        rm -f "$EXT"; pki_err "intermediate signing failed"
        pki_err "retry without regenerating the key: ./pki-init.sh --reuse-slot --replace-ca"
        exit 1
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
