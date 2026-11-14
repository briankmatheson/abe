ABE
===

```
ABE
Block
Exporter
```

![Logo](./logo.svg)


Abe makes it easy to export disk over the NVMe protocol.

Abe listens for connection requests, and then exports requested block
device resources via kernel NVMe Target.  The client can then attach
the drives via nvme cli.

Provided sample client exports a filesystem from that block dev.

INSTALLING
==========

You can build the ABE server using docker with the following command:

```
docker run --rm --user "$(id -u)":"$(id -g)" -v "$PWD":/usr/src/myapp -w /usr/src/myapp rust sh -c 'cargo build --release'
```

create a volume group called "abe" and run the server with:

```
sudo RUST_LOG=info target/release/abe
```

Configuration is by environment (see `debian/abe.default`, installed as
`/etc/default/abe` by the package):

| Variable | Default | Meaning |
|---|---|---|
| `ABE_VG` | `abe` | volume group the volumes are created in |
| `ABE_THIN_POOL` | unset | thin pool in `ABE_VG`; volumes become thin LVs (needed for clones and bases) |
| `ABE_TRADDR` | `0.0.0.0` | address nvmet listens on |
| `ABE_ADVERTISE` | `ABE_TRADDR` | address reported to initiators (`traddr` in replies) |
| `ABE_LISTEN` | `0.0.0.0:443` | API address |
| `ABE_TLS` | `on` | `off`: plain HTTP, no authentication (test harness only; warned about at every start) |
| `ABE_TLS_CERT` | `/etc/abe/cert.pem` | server certificate (PEM, leaf first, chain optional) |
| `ABE_TLS_KEY` | `/etc/abe/key.pem` | its private key (PKCS#8, RSA or EC PEM) |
| `ABE_TLS_CA` | `/etc/abe/ca.pem` | CA bundle client certificates must chain to |
| `ABE_NFT` | `nft` on PATH, else `/usr/sbin/nft` | nft binary for the port fence |
| `ABE_VOL_SIZE` | `10G` | size of a volume made without `?size=`/`?bytes=` |
| `ABE_PORT_MIN` | `23000` | lowest nvmet TCP port handed to exports |
| `ABE_PORT_MAX` | `23999` | highest; abe refuses to start unless `1 <= min <= max <= 65535` |
| `ABE_REEXPORT_WAIT` | `90` | seconds startup waits for the underlay address before serving anyway |
| `ABE_LVM_ALARM` | `10` | seconds an LVM command may run before abe deletes NVMe-oF controllers stuck `connecting` on this host (repeats while it runs; `0` = off) |
| `ABE_FIO_SECONDS` | `5` | seconds of fio writes on each new volume (0: off) |
| `ABE_FIO_RAMP` | `3` | seconds of unmeasured fio warm-up before that |
| `ABE_FIO_BS` | `4k` | fio block size |
| `ABE_FIO_IODEPTH` | `1` | fio writes in flight |
| `ABE_NVMET_PATH` | `/sys/kernel/config/nvmet` | nvmet configfs root (tests only) |
| `ABE_NVME_CLASS_PATH` | `/sys/class/nvme` | where NVMe controllers are listed (tests only) |

TLS
---

The API is HTTPS with **mutual TLS**: abe presents `ABE_TLS_CERT` /
`ABE_TLS_KEY`, and a client is let in only if its certificate chains to
`ABE_TLS_CA`. There is no other authentication; a client without a
valid certificate never reaches a handler (the handshake is refused),
so holding a certificate signed by that CA *is* the right to create and
destroy volumes. Any load error is fatal at startup and names the file.
`ABE_TLS=off` serves plain HTTP for the unprivileged test harness and
standalone experiments; abe warns about it at every start.

On a cluster that already has a CA (xdebbie's `/etc/xdebbie/api-*.pem`,
whose leaf certificates carry serverAuth + clientAuth), point the three
variables at those files. Standalone, make a CA, a server certificate
and a client certificate with openssl (10-year validity; the server SAN
must match the address clients use):

```
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 -subj /CN=abe-ca -addext basicConstraints=critical,CA:TRUE -keyout ca-key.pem -out ca.pem
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj /CN=abe -keyout key.pem -out server.csr
printf 'extendedKeyUsage=serverAuth\nsubjectAltName=IP:10.22.1.1,DNS:abe.example' > server.ext && openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -days 3650 -extfile server.ext -out cert.pem
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj /CN=client -keyout client-key.pem -out client.csr
printf 'extendedKeyUsage=clientAuth' > client.ext && openssl x509 -req -in client.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -days 3650 -extfile client.ext -out client.pem
```

Install `cert.pem`, `key.pem` (root-only) and `ca.pem` under `/etc/abe/`
on the server; give `client.pem`, `client-key.pem` and `ca.pem` to the
client. Then:

```
curl --cacert ca.pem --cert client.pem --key client-key.pem https://10.22.1.1/version
```

`tests/e2e.sh` is the model for scripting abe this way; `/version`
answers `"tls": true` and lists `tls` among its features.

Port fence
----------

NVMe/TCP in the kernel has no x.509 authentication (its TLS is PSK-only),
so abe fences each export's port to **the address its API call came
from**: the TLS peer of the `/configure`, `GET /id` or `/clone` that
exported it, never a parameter. Reaching a volume therefore needs a
certificate *and* that source address. abe owns one nftables table:

```
table inet abe {
    set ports {
        type inet_service
        comment "nvmet ports exported by abe"
    }
    set allowed {
        type ipv4_addr . inet_service
        comment "client ip . nvmet port opened by abe"
    }
    chain input {
        type filter hook input priority filter - 10; policy accept;
        ip saddr . tcp dport @allowed  accept
        tcp dport @ports  tcp flags & (syn | ack) == syn  reject with tcp reset
        meta nfproto ipv6  tcp dport @ports  tcp flags & (syn | ack) == syn  reject with tcp reset
    }
}
```

Only a bare SYN (a new connection attempt) is ever rejected, so an
established session is not cut when its port is moved to another client
(it loses access on its next reconnect), and a local initiator — whose
ephemeral source port could land on an exported port, putting the
SYN-ACK back to it through this same chain — is never reset. abe also
reserves `ABE_PORT_MIN-ABE_PORT_MAX` from ephemeral use at startup
(`net.ipv4.ip_local_reserved_ports`), so a local client cannot grab a
port abe later wants to export on; the default range 23000-23999 is
outside the kernel's ephemeral range (32768-60999) to begin with.

`ports` holds every exported port (including one left over from an
earlier port range), `allowed` who may open each. The table goes up before
anything is exported (startup fails with exit 4 if nft cannot install
it) and is **replaced atomically** on every re-export pass, already
holding every live export. An export is opened right after configfs is
set up and torn down again if the fence cannot be opened; a delete
closes the port before the export goes. `GET /id` on an exported volume
moves its port to the caller, so a VM that moved to another host is
reachable from there after its next attach. The client is recorded in
the `abe_client` tag and shown as `client` in `/volumes` and in replies.

A volume exported by an older abe has no `abe_client` tag. On the first
re-export pass abe looks for an **established TCP connection** to its
port (`/proc/net/tcp`); exactly one peer is *adopted* (fence opened to
it, tag written, `adopted <ip> for <id> on <port>` logged). With none or
several the port stays closed, the id is listed in `reexport.closed`
and `/utilization.warnings` says `N volume(s) exported with no client;
closed until attached again`; the next `GET /id/<id>` opens it. `nft
list table inet abe` shows the fence; if anything has mangled it, `GET
/reexport` rebuilds it from scratch. The fence is IPv4 only: a request
from an IPv6 address (other than v4-mapped) is a 400, and IPv6 to the
port range is rejected outright. abe does not touch any other firewall
rule; open 443 and the port range on the interface initiators use.

Ports
-----

Every export gets its own nvmet port on `ABE_TRADDR`: the **lowest free
TCP port** in `ABE_PORT_MIN`..`ABE_PORT_MAX` (23000-23999), so the port a
delete frees is the next one handed out. Port directories in configfs
are named after the port number (`ports/23002`); ones made by older
versions (`ports/1`, `ports/2`) keep working, since only `addr_trsvcid`
is consulted. When the range is full, `/configure`, `/clone` and `/id`
answer `503` with `{"error": "no free nvmet port in 23000-23999 (N
exported)"}` and nothing is left behind. Each port is open only to the
address that asked for it (see "Port fence"); beyond that abe does not
touch the host firewall, so open 443 and 23000:23999 on the interface
initiators use, e.g. `ufw allow in on wg-flock proto tcp from
10.22.0.0/16 to any port 23000:23999`.

Exports live only in configfs, so a reboot or a fresh `nvmet` module
load erases them. **At startup abe exports every volume again**, before
it starts serving, each on the port recorded in its `abe_port` tag when
that port is free (otherwise the lowest free one, with a warning that
it moved). While the underlay address is not up yet nvmet refuses with
`EADDRNOTAVAIL`; abe retries every 2 s for `ABE_REEXPORT_WAIT` seconds,
then serves anyway and keeps retrying in the background every 10 s. One
log line sums the pass up (`exported=N already=M failed=K moved=J`);
`GET /reexport` runs it again on demand and `/utilization` carries the
last result under `reexport`.

Tags
----

Per-volume metadata is kept as LVM tags on the LV, so it is in the VG
metadata and survives reboots without a state file:

| Tag | Meaning |
|---|---|
| `abe_port=<n>` | trsvcid this volume is exported on; re-export reuses it |
| `abe_name=<name>` | the caller's name, for idempotent create (`?name=`) |
| `abe_base=<image>` | this volume is the base for `<image>` |
| `abe_sealed` | the base is filled and frozen: never exported, clone-only |
| `abe_client=<ipv4>` | the address its port is fenced to (the last caller); re-export opens it to the same |

`name` and `image` values must match `[A-Za-z0-9._+:-]{1,128}` (400
otherwise).

API
===

| Request | Effect |
|---|---|
| `GET /configure?size=5G` or `?bytes=N` | create a volume of that size (default `ABE_VOL_SIZE`; GPT + one partition labelled with its id) and export it; the reply carries the resulting `bytes` |
| `GET /configure?...&raw=true` | same, but leave the volume blank (VM disk images bring their own partition table) |
| `GET /configure?...&name=<name>` | idempotent create: if a volume tagged `abe_name=<name>` exists it is exported if needed and returned with `"existing": true` (no fio, `perf: null`); 409 if it is smaller than requested |
| `GET /configure?base=<image>&bytes=N` | make (or return) the base volume for `<image>`: raw, no fio; the reply adds `"base"` and `"sealed"`; 409 if the existing base is smaller than N; a sealed base is returned without a port |
| `GET /seal/<id>` | freeze a filled base: unexport it, tag `abe_sealed`; idempotent; 400 if `<id>` is not a base; reply `{"id","base","sealed":true,"bytes"}` |
| `GET /id/<id>` | (re-)export an existing volume; idempotent; 409 on a sealed base |
| `DELETE /id/<id>` | unexport and remove the volume; idempotent; allowed on a base (its clones keep their data) |
| `GET /volumes` | list every volume: `id`, `bytes`, `port` (if exported), `traddr`, `nqn`, `used_bytes`, `data_percent`, `origin`, `layers`, `warning`, `base`, `sealed`, `name`, `client` (the address the fence opens its port to) |
| `GET /clone/<id>` or `?bytes=N[&name=..]` | create a new volume as a thin snapshot of `<id>` (shares blocks until written; optionally grown to N bytes) and export it; needs `ABE_THIN_POOL`; a base must be sealed first (409); `name` works as for `/configure` |
| `GET /utilization` | thin pool (or VG) `bytes`, `used_bytes`, `free_bytes`, `data_percent`, `metadata_percent`, `provisioned_bytes`, `vg_bytes`, `vg_free_bytes`, `volumes`, `max_layers`, `warnings`, `reexport` |
| `GET /reexport` | run the startup re-export pass again (rebuilds the fence); reply `{"exported","already","failed":[ids],"moved","closed":[ids],"at"}` |
| `GET /version` | `{"version", "features": [..], "tls"}`; features are `reexport`, `ports`, `name`, `trim`, `tls`, `fence`, and with a thin pool `base` and `clone` |

Every call that changes LVM or configfs runs under one process-wide
lock, so concurrent creates get distinct ports and a failed create
leaves neither an LV nor configfs entries behind. fio runs outside the
lock.

Clones are LVM thin snapshots, so a clone of a clone adds a layer every
time. `layers` counts the origins beneath a volume; past
`MAX_SNAPSHOT_LAYERS` (10) the volume carries a `warning`, the clone reply
does too, `/utilization` lists it under `warnings`, and abe logs it.

Bases
-----

A base is a volume tagged `abe_base=<image>`, meant to hold a disk
image once so that every VM root can be a thin clone of it instead of a
full copy. The flow is: `GET /configure?base=<image>&bytes=N` (returns
the same base for the same image, exported while unsealed), fill it
over NVMe/TCP, `GET /seal/<id>`, then `GET /clone/<id>?bytes=..&name=..`
per VM. A sealed base is never exported again. To refresh an image,
`DELETE /id/<base id>`; existing clones keep their data and the next
`?base=` request makes a new one. Bases are not made read-only with
`lvchange -p r` (the bit would carry over to snapshots); the tag and the
API refusals protect them.

fio check
---------

Replies carry `id`, `port` (nvmet trsvcid), `traddr`, `nqn` (== id),
`client` (the address the port is open to: the caller's) and a
ready-to-run `nvme connect` line in `message`. `/configure` also runs
fio on the new volume: random direct writes at `ABE_FIO_BS` (default 4k)
with `ABE_FIO_IODEPTH` (default 1) in flight, for `ABE_FIO_RAMP` seconds
of unmeasured warm-up (default 3; queues, caches and the first
thin-chunk allocations settle) and then `ABE_FIO_SECONDS` measured
(default 5, 0 disables the run). The region is at most 1 GiB: from the
start of a raw volume, and **inside partition 1** of a non-raw one (from
1 MiB to 1 MiB short of the end, so neither GPT copy is touched; parted
confirms afterwards that partition 1 is still there). Volumes under
about 18 MiB skip the run. **Afterwards the region is trimmed**:
`blkdiscard` on a thin volume gives every chunk fio allocated back to
the pool and makes it read as zeros, `blkdiscard --zeroout` on a thick
one just blanks it. The reply reports `perf`: `write_lat_us` (mean
completion latency: what one synchronous small write costs on this pool),
`write_iops`, `write_mib_s`, `bs`, `iodepth`, `seconds` (the measured
window) and `trimmed` (false if the trim failed; the volume is still
returned). The same numbers go to the log, so the pool's behaviour over
time is in the journal. If the thin pool has `discards=ignore` the trim
frees nothing; abe warns at startup and suggests `lvchange --discards
passdown <vg>/<pool>`. Each namespace is exported with `device_uuid` set
to the volume id, so initiators get a stable
`/dev/disk/by-id/nvme-uuid.<dashed id>` path.

Tests
-----

`cargo test` covers the pure parts (port choice, fio region, lvs and tag
parsing, validation, the nft script and JSON, `/proc/net/tcp` parsing,
the TLS configuration and a TLS round trip against the test-only PKI in
`tests/certs/`). `sudo tests/e2e.sh` drives a running abe on a host with
a thin pool through every scenario (14: the volume lifecycle, a stop /
configfs wipe (`tests/nvmet-wipe.sh`) / start round trip, TLS without a
client certificate, the fence from a second local address, adoption
across a restart, and rebuilding the fence), reading the TLS settings
from `/etc/default/abe`. `tests/lint-links.sh` checks the repo links.

Use the client under extra/ for an example of connecting to the server
and exporting block devices from your favorite Linux client:

```
./client.sh
```

The provided client will connect to the abe server, create and export
a block dev, mount it, and export it via nfs.  A simple persistence
mechanism makes the client default to attaching to the previous drive.
You can override this behavior by deleting /root/.abe.

Also included under extra is a script to create an abe client VM.

```
./create-abc
```

The create-abc script produces a qcow2 image that is built with
virt-install and is customized to run a hardened nfs server 
(using the awesome HARDN project).  

```
virt-install -n abc --memory 1024 --vcpus 4 --import --disk /var/lib/libvirt/images/abc.qcow2 --osinfo debian11 --autoconsole text
```

will create a vm called abc with the specified parameters and boot
that disk image.  The resulting vm will connect to and export storage
at /export/nfs.
