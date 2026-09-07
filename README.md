# Pamperins LAN — PKI Manager

TUI and web dashboard for the `pamperins.lan` internal PKI.

Both front ends call the same shell library (`lib/pki-lib.sh`), so a probe or a
fix behaves identically whether you run it from the terminal or the browser.

```
pki-manager.sh ─┐
                ├─ lib/pki-lib.sh ─→ openssl / ssh / ykman / occ
pki-web.py ─────┘   (probes + actions)
```

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
| `renew` | runs `~/pki/renew-certs.sh` — that script stays the source of truth |
| `deploy <host>` | pushes certs for every role the host has, then restarts what needs it |
| `trust-push <host>` | installs the root CA into the system trust store |
| `webmin-push <host>` | writes **leaf + intermediate** to `miniserv.cert`, key to `miniserv.pem` |
| `webmin-fix <host>` | repoints `miniserv.conf` at `/etc/webmin/` |
| `ldap-fix <host>` | rewrites `TLS_CACERT` to `pamperins-root-ca.crt` |
| `samba-fix <host>` | `chown root:root` on the Samba TLS dir, then restarts Samba |
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

## YubiKey

The root CA private key is in PIV slot 9c and never leaves the key.

| Action | Needs |
|---|---|
| `yk-info`, `yk-slot`, `yk-retries`, `yk-export-cert` | nothing — safe to run anywhere |
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
