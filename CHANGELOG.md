# Changelog

## Unreleased

- LVM watchdog: an LVM command still running after `ABE_LVM_ALARM`
  seconds (default 10) makes abe delete every NVMe-oF controller on the
  host that is stuck `connecting`, and again at each further interval.
  LVM scans every block device, so a controller whose target was gone
  (`ctrl_loss_tmo=off`) hung `lvchange` forever; abe held its lock
  behind it, the API stopped accepting and `/version` timed out.

## 0.5.2

- `/clone` retried with the same `name` returned the existing volume
  with `bytes` twice in the JSON (once from the export, once from the
  clone reply); xdebbied's reader refused it (`duplicate field bytes`),
  so a VM whose first clone succeeded but whose reconcile pass was
  retried never got its root disk. One `bytes` now; e2e re-asks a clone.

## 0.5.1

- Startup checks `ABE_LISTEN` and loads the TLS material **before**
  touching nvmet, the port reservation or the nftables fence, so a bad
  path in `/etc/default/abe` exits 3 with nothing changed on the host.
- `blkdiscard --force`: util-linux >= 2.38 refuses to discard a device
  carrying a signature, which made every GPT volume's `/clone` and
  `/seal` trim report `trimmed: false`.
- `make install` / `make deploy` reinstall even at the same version and
  keep the local `/etc/default/abe` (`Dpkg::Options::=--force-confold`);
  the package revision comes from `[package.metadata.deb] revision`.
  `make deploy` says plainly when the remote `/version` check fails.
- (0.5.1-2) Upgrading the package restarts abe if it was running: `prerm` stops it
  (as before) and notes that it was active, `postinst` starts the new
  one. A plain `apt install ./abe-block-exporter_*.deb` used to leave
  abe stopped, exports and fence down, until someone noticed.

## 0.5.0

The API moves to HTTPS with mutual TLS, and every nvmet port is fenced
to the address that asked for it.

### Port range 23000-23999; fence keyed on exported ports

- The default nvmet port range moves from 44001-44999 to 23000-23999,
  outside the kernel's ephemeral range (32768-60999). Override with
  `ABE_PORT_MIN`/`ABE_PORT_MAX` as before; a volume recorded on an old
  port is moved into the range at the next re-export (`moved` in the
  summary) and stays fenced on the old port until then.
- The fence rejects SYNs to the `ports` set (every exported port) rather
  than to the configured range, so exports that survive a range change
  are still fenced. `nft list table inet abe` shows both sets.
- Firewalls that allowed 44000:44999 need the new range (ufw:
  `allow in on wg-flock proto tcp from 10.22.0.0/16 to any port 23000:23999`).

### Fence rules judge SYNs only; port range reserved from ephemeral use

- The reject rules match only bare SYNs. For a local initiator both
  directions of a connection pass the input hook, and with the
  ephemeral port range (32768-60999) overlapping 44001-44999 the
  SYN-ACK back to it was reset about one connection in thirty — an
  `nvme connect` opens seventeen, so roughly every other local connect
  timed out (`failed to connect socket: -110`). Found by e2e scenario 8.
- At startup abe appends its port range to
  `net.ipv4.ip_local_reserved_ports` (best effort, logged), so a local
  client can no longer take a source port abe later exports on.

### TLS

- The API is served over TLS with a **required client certificate**:
  abe presents `ABE_TLS_CERT` / `ABE_TLS_KEY` (default
  `/etc/abe/cert.pem`, `/etc/abe/key.pem`) and accepts only clients
  chaining to `ABE_TLS_CA` (`/etc/abe/ca.pem`). A missing or unreadable
  file is fatal at startup (exit 3) and names the path.
- `ABE_LISTEN` now defaults to `0.0.0.0:443` (was `:80`).
- `ABE_TLS=off` keeps plain HTTP for the unprivileged test harness;
  warned about at every start.
- `/version` reports `"tls": true|false` and lists `tls` and `fence`
  among its features.
- `Listening on https://…` at startup.

### Port fence

- abe owns the nftables table `inet abe`: a set of `(client ip, port)`
  pairs and an input chain that resets every other TCP connection to
  `ABE_PORT_MIN-ABE_PORT_MAX` (IPv6 too). Installed before anything is
  exported (exit 4 if nft fails), rebuilt atomically on every
  re-export pass with every live export already in it. `ABE_NFT`
  overrides the binary; the package depends on `nftables` and the unit
  orders after `nftables.service`.
- `/configure`, `GET /id/<id>` and `/clone/<id>` open the new port to
  the **TLS peer address of the request** (never a parameter). If the
  fence cannot be opened the export is torn down and the request fails.
  `GET /id` on an exported volume moves its port to the caller. A
  delete or seal closes the port before the export goes.
- Requests from an IPv6 address (other than v4-mapped) are a 400:
  `fence needs an IPv4 client address`.
- New tag `abe_client=<ipv4>`; `client` in `/configure`, `/id`,
  `/clone` replies and in `/volumes` (what the fence allows right now).
- Volumes exported by 0.4.0 have no client tag: on the first re-export
  pass the single established connection to their port is **adopted**
  (fence opened, tag written, `adopted <ip> for <id> on <port>`
  logged); with none or several the port stays closed, the id is in
  `reexport.closed` and `/utilization.warnings` carries `N volume(s)
  exported with no client; closed until attached again`. The next
  `GET /id` opens it.
- `GET /reexport` rebuilds the table from scratch.

### Packaging and tests

- `debian/abe.default` documents `ABE_TLS*` and `ABE_NFT`; the
  "installed without authentication" postinst banner is gone;
  `SECURITY_AUDIT.md` rewritten for the new controls and what the fence
  does not do.
- `make install` / `make deploy` verify `/version` with the TLS
  settings from the target's `/etc/default/abe`.
- `tests/e2e.sh` reads the TLS settings from `/etc/default/abe`, sends
  every request through `$CURL`, and adds scenarios 10–14: no client
  cert refused, fence after configure/DELETE, fence from a second local
  address (`curl --interface`, `nvme connect --host-traddr`), adoption
  across a restart, and `GET /reexport` after `nft destroy table inet
  abe`. `tests/nvmet-wipe.sh --all` destroys the fence too.
- Unit tests for the nft script (golden, and loaded for real in a user
  namespace where allowed), `nft -j` parsing, `/proc/net/tcp` parsing,
  the TLS configuration against the test-only PKI in `tests/certs/`,
  the client verifier refusing another CA, and a TLS round trip with
  and without a client certificate.

## 0.4.0

- One process-wide lock for every LVM/configfs mutation; per-volume
  metadata as LV tags (`abe_port`, `abe_name`, `abe_base`,
  `abe_sealed`).
- Lowest free nvmet port in `ABE_PORT_MIN-ABE_PORT_MAX`; 503 when the
  range is full.
- Every volume re-exported at startup and on `GET /reexport`, with
  retries while the underlay address is missing.
- fio inside partition 1, then trim; `perf.trimmed`.
- `?name=` idempotent create; base volumes, `/seal`, `/clone` from a
  sealed base; `/version`.
- Packaged as `abe-block-exporter` (Conflicts with Debian's `abe`).
