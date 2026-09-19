# Pamperins LAN — PKI Manager

TUI and web dashboard for the `pamperins.lan` internal PKI.

Both front ends call the same shell library (`lib/pki-lib.sh`), so a probe or a
fix behaves identically whether you run it from the terminal or the browser.

```
pki-init.sh  ────┐   create the CA        (once, YubiKey, PIN + touch)
renew-certs.sh ──┤
pki-manager.sh ──┼─ lib/pki-lib.sh ─→ openssl / ssh / ykman / occ
pki-web.py  ─────┘   (probes + actions)
```

`pki-init.sh` builds the CA. `renew-certs.sh` issues and renews leaf certs and
is safe for cron. The other two manage and deploy what those produce.

## Install

```bash
sudo apt install openssl openssh-client sshpass yubikey-manager \
                 opensc libengine-pkcs11-openssl ldap-utils
pip3 install -r requirements.txt

cp pki.conf.example ~/pki/pki.conf
chmod 600 ~/pki/pki.conf        # the scripts warn if it is not 600
$EDITOR ~/pki/pki.conf
```

Everything host- and credential-specific lives in `~/pki/pki.conf`. Nothing is
hardcoded in the scripts. Override the location with `PKI_CONF=/path/to/conf`.

## Settings menu

Rather than editing `pki.conf` by hand:

```bash
./pki-manager.sh          # then press s
./pki-manager.sh --run settings
```

It sets the SSH user, key file, password, sudo password, port and per-host
addresses, and can test ssh-plus-root against every host so you find out
straight away whether the credentials work.

Everything is written to `$PKI_CONF` (`~/pki/pki.conf` by default), which stays
mode 600. Passwords are typed hidden and shown back only as `******** (set)`;
enter `-` to clear one. Because secrets are typed, the menu is terminal-only
and is not reachable from the web UI.

Note that a `pki.conf` sitting next to the scripts is **not** read — the
scripts use `$PKI_CONF`. Editing the wrong copy is easy and silent, so the
dashboard and preflight now warn when a stray one exists.

## SSH access

Every remote action runs over ssh as `SSH_USER` (default `root`) and needs
root on the far end. Key auth is assumed — the scripts use `BatchMode`, so a
password-only host fails immediately with `Permission denied` rather than
prompting.

Either give your key root access:

```bash
ssh-copy-id root@10.0.2.2        # repeat per host
```

or run as yourself and let sudo do the privileged part, in `pki.conf`:

```bash
SSH_USER=rpamperin
SSH_KEY=/home/rpamperin/.ssh/id_ed25519
#SUDO_PASS=...                   # only if that user lacks passwordless sudo
```

`./pki-manager.sh --run preflight` tells you which hosts are reachable, which
refuse auth, and which can reach root.

## Starting from nothing

If there is no CA yet, build one. Review the plan first — creating the root key
on the YubiKey cannot be undone:

```bash
./pki-init.sh --dry-run     # prints every command, changes nothing
./pki-init.sh               # asks for the PIV PIN and a touch
```

This generates the Root CA keypair **on the YubiKey** (slot 9c, never
extractable), self-signs it with proper CA extensions, then creates an
intermediate CA on disk signed by that root. It refuses to overwrite a slot
that already holds a key, or an intermediate that already exists.

If anything fails after the key is generated, retry without regenerating it:

```bash
./pki-manager.sh --run yk-pkcs11    # what the token exposes, and which URI works
./pki-init.sh --reuse-slot          # keep the key in 9c, redo the rest
```

`yk-pkcs11` exists because a wrong `YK_ROOT_KEY_URI` only shows up at signing
time. Init resolves the URI itself as soon as the slot has a certificate and
tells you what to put in `pki.conf` if the default was wrong.

### If a slot write seems to hang

Writing to a PIV slot can require a physical touch, and nothing on screen says
so — the key just blinks. If a step stops right after you enter the PIN, touch
the key. A countdown bar appears while it waits, so you can see how long is
left before it gives up:

```
   [##########..............]   68s left - touch the key if it is blinking
```

It starts a few seconds in, so it never draws over the PIN prompt, and it is
suppressed when output is not a terminal.

Storing the root certificate in the slot is a convenience, not a requirement:
the copy under `root-ca/` is what signs and what gets distributed, and the slot
only needs *some* certificate for PKCS#11 to expose the private key. So
`pki-init.sh` warns and carries on if that write fails, and you can do it later:

```bash
./pki-manager.sh --run yk-import-root
```

### Touch-only signing (no PIN)

Signing can require just a touch, with no PIN at all:

```bash
./pki-init.sh --touch-only --replace-slot
```

The catch is that a key's PIN policy is burned in when the key is generated
and cannot be altered later, so this needs a **new** root keypair — which
orphans everything the old root signed. It is cheap before you have issued or
distributed anything, and expensive afterwards. `pki-init.sh` refuses to
combine `--touch-only` with `--reuse-slot` or `--intermediate-only` for that
reason, and will not silently replace an occupied slot.

Understand the trade: a touch proves someone is physically present, not who
they are. With no PIN, anyone who picks up the key can sign with your root CA.
The PIN is what makes a stolen key useless. Reasonable for a home lab where
the key lives on your keyring; not for a root CA that matters to anyone else.

If the key is already generated that way, set `YK_NO_PIN=1` in `pki.conf` so
the tooling stops asking.

### The management key

Writing to a PIV slot needs the management key, separate from the PIN. The
tidiest answer is to keep it on the key itself:

```bash
./pki-manager.sh --run yk-protect-mgmt
```

That generates a random management key, stores it on the YubiKey protected by
your PIN, and retires the factory default — which is published, and lets
anyone holding the key rewrite its slots. Afterwards ykman asks for the PIN
instead, and there is nothing on disk to protect or back up.

If you would rather hold it yourself, set `YK_MGMT_KEY` in `pki.conf` or point
`YK_MGMT_KEY_FILE` at a mode-600 file. Both work, but ykman only accepts the
management key as a command-line argument, so it is briefly visible in `ps`
to local users while a slot write runs. `yk-protect-mgmt` has no such window.

### How many times it asks for the PIN

A full `pki-init.sh` run asks three times, and that is the minimum for a
PIN-protected key:

| Prompt | Purpose |
|---|---|
| `PIV PIN (hidden)` | resolves the key URI, then satisfies the token login for both signatures |
| `Enter PKCS#11 key PIN` | root self-signature |
| `Enter PKCS#11 key PIN` | intermediate signature |

The last two are PIV's rule for slot 9C — a PIN check immediately before every
signature. Removing the first would make it four, because openssl would then
ask for the token PIN separately at each signing.

This is a one-off. `renew-certs.sh` signs with the intermediate on disk and
needs no PIN, no touch and no YubiKey at all; the key is only needed again to
re-sign the intermediate, once every `INT_CA_DAYS` (five years by default).

### The PIN, and why slot 9C asks twice

PIV defines slot 9C as the Digital Signature key and requires a PIN check
immediately before **every** signature. OpenSC marks the key
`CKA_ALWAYS_AUTHENTICATE`, so libp11 performs a second, context-specific login
that `-passin` does not reach — it prompts again, and an unanswered prompt
surfaces as the unhelpful `Invalid PIN length`.

Init therefore asks for the PIN once, checks the length locally (a PIV PIN is
6–8 characters, and an impossible one is never sent to the card), and passes it
through an RFC 7512 `pin-source` file at mode 600 so it stays out of `ps`. The
PIN is held only in the process environment and a temporary file removed on
exit — never written to `pki.conf`, never logged.

A wrong PIN costs one of three tries before PIV blocks the key, so URI
resolution stops the moment a PIN is rejected rather than spending the rest.
Check the counter any time with:

```bash
./pki-manager.sh --run yk-retries
```

Afterwards the root is only needed to re-sign the intermediate. Day-to-day
issuance uses the intermediate and needs no PIN and no touch.

### Cutover onto a live LAN

Order matters. Trusting the new root is additive and safe; swapping certs is
not. Do it in this order or LDAPS and Samba break mid-change:

Check first. `preflight` verifies config, tools, the CA, the issued certs and
ssh-plus-root on every host, changes nothing, and prints the fix for whatever
fails:

```bash
./pki-manager.sh --run preflight
```

Do not start until it says `ready`. Then, one step at a time — read the output
of each before running the next:

```bash
./renew-certs.sh --force                    # 1. issue the new service certs
./pki-manager.sh --run trust-push-all       # 2. trust the new root EVERYWHERE
./pki-manager.sh --run verify-tls           #    confirm before touching certs
./pki-manager.sh --run deploy-all           # 3. now swap the certs over
./pki-manager.sh --run ldap-fix-all         # 4. repoint ldap.conf
./pki-manager.sh --run trust-cleanup-all    # 5. only once everything is green
```

Pasting all six at once runs each regardless of whether the one before it
failed, which buries the real error. Chain them with `&&` if you want them
unattended.

Step 2 never removes an anchor. If a host already has one at the same path,
the old one is kept alongside as `*-superseded-<date>.crt` and stays trusted,
so certs still in service keep validating. Step 5 removes those — run it only
after `verify-tls` shows every endpoint on the new root.

## Use

```bash
./pki-manager.sh                       # dashboard + menu
./pki-manager.sh --status              # dashboard, then exit
./pki-manager.sh --status-json         # same data as JSON
./pki-manager.sh --run deploy dc       # one action, non-interactively
./pki-manager.sh --list-actions

./pki-web.py                           # http://127.0.0.1:7443
```

For the web UI as a service, edit and install `pki-web.service`.

## Dashboard

| Card | Shows |
|---|---|
| CONFIG | whether `pki.conf` loaded, and whether it is mode 600 |
| YUBIKEY | slot 9c key present, PIN retries left, cert on the key |
| CERTIFICATES | days remaining on the root CA, intermediate, and every issued cert |
| SERVERS | per-host reachability of ssh and each role's port |
| LDAPS | live chain verification against `ldaps://dc:636` |
| WEBMIN CHAIN | how many certs Webmin actually presents (1 = intermediate missing) |
| NEXTCLOUD | `turnOffCertCheck` vs whether trust really works |

Green / amber / red follow `WARN_DAYS` (30) and `CRIT_DAYS` (7).

## Actions

| Action | What it does |
|---|---|
| `renew` | runs `renew-certs.sh`, the source of truth for renewal logic |
| `issue <host>` | re-issue one host's cert immediately, ignoring the renewal window |
| `deploy <host>` | pushes certs for every role the host has, then restarts what needs it |
| `trust-push <host>` | installs the root CA into the system trust store |
| `webmin-push <host>` | writes **leaf + intermediate** to `miniserv.cert`, key to `miniserv.pem` |
| `webmin-fix <host>` | repoints `miniserv.conf` at `/etc/webmin/` |
| `ldap-fix <host>` | rewrites `TLS_CACERT` to `pamperins-root-ca.crt` |
| `samba-fix <host>` | `chown root:root` on the Samba TLS dir, then restarts Samba |
| `trust-cleanup <host>` | removes superseded root anchors once cutover is done |
| `nextcloud-certcheck auto` | tests trust, then sets `turnOffCertCheck` to match |
| `verify-tls [host]` | subject, issuer, expiry, chain length and verify result per endpoint |
| `logs [n]` | tails the manager log and the last renewal logs |

Each has an `-all` variant where it makes sense. Every action re-runs the status
probes when it finishes.

### Known breakages these actions fix

- **Webmin on dc points at `/var/lib/samba/private/tls/`** after an AD join —
  `webmin-fix` rewrites `keyfile`/`certfile` and backs up the old conf.
- **Webmin serves the leaf alone** — `webmin-push` bundles leaf + intermediate,
  and the dashboard's chain count shows `1` until it does.
- **Samba refuses to start unless its TLS files are `root:root`** — every deploy
  ends with the chown, and `samba-fix` does it standalone.
- **`/etc/ldap/ldap.conf` points at the stale `pamperins-ca.crt`** — `ldap-fix`
  repoints it and reports the old value.
- **Nextcloud `turnOffCertCheck` drifts** — `auto` mode decides from a live
  fetch instead of guessing, so the bypass is on only while trust is broken.

## Automating renewal

`renew-certs.sh` signs with the intermediate only, so it needs no PIN, no touch
and no YubiKey — it runs unattended. Renew weekly; anything due within
`RENEW_BEFORE_DAYS` (30) gets reissued, everything else is skipped:

```cron
17 3 * * 1  cd /home/YOURUSER/pki-manger && ./renew-certs.sh && ./pki-manager.sh --run deploy-all
```

Check what it would do without changing anything:

```bash
./renew-certs.sh --list
```

Only root operations need the hardware: re-signing the intermediate when it
nears expiry (`INT_CA_DAYS`, 5y by default), which is `yk-sign-intermediate`.

## YubiKey

The root CA private key is in PIV slot 9c and never leaves the key.

| Action | Needs |
|---|---|
| `yk-info`, `yk-slot`, `yk-retries`, `yk-export-cert`, `yk-pkcs11` | nothing — safe to run anywhere |
| `yk-protect-mgmt` | current management key (enter = factory default) |
| `yk-import-root` | management key or PIN, plus a touch |
| `yk-test` | PIN + touch |
| `yk-sign-intermediate [csr]` | PIN + touch — signs via the PKCS#11 engine |
| `yk-change-pin`, `yk-change-puk`, `yk-unblock-pin`, `yk-change-mgmt` | PIN / PUK / mgmt key |

**The PIN is never stored in `pki.conf` and is never accepted over HTTP.**
`ykman` prompts on the terminal, so PIN and touch operations run only from the
TUI on the console; the web UI refuses them and says so. The dashboard surfaces
remaining PIN attempts, because a locked key is the failure you want to catch
before renewal day rather than during it.

Signing the intermediate needs `opensc` plus `libengine-pkcs11-openssl`; set
`PKCS11_MODULE` and `YK_ROOT_KEY_URI` in `pki.conf` if yours differ.

## Web UI notes

- Binds `127.0.0.1:7443`. Binding anywhere else without `WEB_TOKEN` is refused.
- Set `WEB_TOKEN` (`openssl rand -hex 24`) for a login gate; `WEB_TLS_CERT` /
  `WEB_TLS_KEY` serve it over HTTPS.
- Only actions in the catalogue can run; hosts and modes are validated against
  `pki.conf` in both Python and the shell.
- POSTs carry a CSRF token, one action runs at a time, and output streams live.
- Auto-refreshes every 60s.

It runs Flask's development server — fine for one admin on localhost, which is
what it is for. Put it behind a real WSGI server if that ever changes.

## Adding a host

Append the id to `HOSTS` and define its address and roles:

```bash
HOSTS="dc gateway ns1 newbox"
HOST_newbox_ADDR=10.0.2.5
HOST_newbox_ROLES="apache webmin"
```

Roles (`samba ldaps webmin nextcloud apache dns`) drive which ports get probed
and what `deploy` pushes. No script changes needed.
