# ABE Security Audit

Revised for 0.5.0. The original audit (0.1) is kept at the bottom with
each finding's status; the first section is what matters now.

## Controls in 0.5.0

### Mutual TLS on the API

The API is served only over TLS with a required client certificate
(`rustls`, `WebPkiClientVerifier`, no unauthenticated clients). A client
whose certificate does not chain to `ABE_TLS_CA` never reaches a
handler: the handshake is refused. Holding such a certificate is the
whole authorisation model: any authenticated client may create, attach,
clone, seal and delete any volume. There is no per-volume ownership and
`DELETE /id/<id>` does not check the caller against the volume's
`abe_client` tag; the certificate is the authority for destroy.

`ABE_TLS=off` is plain HTTP with nothing in front of it, for the
unprivileged test harness. abe logs a warning at every start with it.

### The nvmet port fence

NVMe/TCP in the kernel offers no x.509 authentication (its TLS is
PSK-only) and `allowed_hosts` by hostnqn is unverifiable, so the control
on *who can read a volume's bytes* is an nftables table abe owns
(`inet abe`): a set of `(client ipv4, port)` pairs and an input chain
that resets every other TCP connection to the nvmet port range, IPv6
included. The client address is the TLS peer of the request that
exported the volume (`/configure`, `GET /id`, `/clone`), never a request
parameter, so opening a port to an address requires a certificate *and*
connecting from that address. The table goes up before any export does
(startup fails otherwise), is rebuilt atomically on every re-export
pass, and a port is closed before its export is torn down.

What the fence does **not** do:

- It trusts the source address. On an untrusted L2 (a flat LAN with
  hosts that can spoof or ARP-poison) a source address is not an
  identity. It is sound behind a WireGuard underlay, where the
  address is bound to a peer key, or on any link where every host is
  trusted not to spoof. Do not expose the nvmet range on a flat LAN
  and rely on the fence alone.
- It does not encrypt or authenticate the NVMe/TCP stream itself.
  Confidentiality and integrity of the data path come from the
  underlay (WireGuard) or nothing.
- It is IPv4 only. IPv6 clients of the API are refused (400) and IPv6
  to the port range is rejected.
- Volumes exported by an older abe have no recorded client. On the
  first pass, exactly one established connection to the port is
  adopted; otherwise the port stays closed until the next `GET /id`.
  The adoption trusts whoever was connected at that moment.
- Only new connection attempts (bare SYNs) are judged. A session that
  was established while its address was allowed keeps running after the
  port is moved to another client until it reconnects; `GET /id` from
  the new client does not cut the old one. The reason is correctness
  for local initiators: both directions of a local connection pass the
  input hook, and resetting anything but SYNs would reset a SYN-ACK
  back to an ephemeral port that happens to be exported. The default
  range 23000-23999 is outside the ephemeral range, and abe reserves
  it anyway (`net.ipv4.ip_local_reserved_ports`).
- The fence is keyed on exported ports, not the configured range, so a
  port left over from an earlier range stays fenced after the change.
- Other base chains on `input` still run (`accept` only ends abe's
  chain); abe never widens another table's policy.

### Input validation

Volume ids are 32 hex characters (`is_volume_id`) and anything else in a
path is answered 404 without touching LVM or configfs. `name` and
`base` values are restricted to `[A-Za-z0-9._+:-]{1,128}` before they
become LVM tags. Sizes go through `lvcreate` as `-L`/`-V` arguments,
never a shell.

### Process

Every LVM/configfs mutation runs under one process-wide lock, which
removes the port-allocation race of early versions. External tools are
run with `Command` argument vectors; no shell is involved. The
`.unwrap()`s left are on startup configuration (bad listen address, no
TLS material, no nft) and exit with a distinct code.

### Remaining

- One certificate class: there is no distinction between an operator
  and a node, nor per-volume ownership. A compromised node certificate
  can delete every volume on the ABE it can reach.
- No request logging of the client certificate's subject (only the
  peer address is logged).
- No rate limiting; `/configure` runs fio for several seconds per
  volume, so an authenticated client can keep the box busy.
- The systemd unit runs as root (configfs, LVM and nft need it).

## Original findings (0.1) and status

1. **No authentication** — *fixed in 0.5.0* by mutual TLS (above).
2. **Command injection via id** — *fixed*: ids are validated as 32 hex
   characters; tag values are whitelisted; no shell.
3. **Arbitrary firewall rules (`ufw allow`)** — *fixed*: abe no longer
   calls ufw. It owns exactly one nftables table of its own and nothing
   else.
4. **Hardcoded volume group** — *fixed*: `ABE_VG`, `ABE_THIN_POOL`.
5. **No input validation** — *fixed* for ids, names, sizes and the port
   range; capacity is reported by `/utilization` and refused by LVM.
6. **Excessive `.unwrap()`** — *mostly fixed*; the rest are at startup.
7. **Port allocation race** — *fixed* by the `OPS` lock.
8. **Listening on 0.0.0.0** — *mitigated*: still the default, but
   `ABE_LISTEN` and `ABE_TRADDR` bind to one address, and with mTLS a
   wide bind exposes only the handshake.
9. **No TLS** — *fixed in 0.5.0*.
10. **No volume lifecycle** — *fixed*: `/volumes`, `DELETE /id`,
    `/utilization`.
11. **No metrics / health** — *partly*: `/version` and `/utilization`
    serve as health; no Prometheus endpoint.
