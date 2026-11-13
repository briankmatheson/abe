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
| `ABE_LISTEN` | `0.0.0.0:80` | HTTP API address |
| `ABE_VOL_SIZE` | `10G` | size of a volume made without `?size=`/`?bytes=` |
| `ABE_PORT_MIN` | `44001` | lowest nvmet TCP port handed to exports |
| `ABE_PORT_MAX` | `44999` | highest; abe refuses to start unless `1 <= min <= max <= 65535` |
| `ABE_REEXPORT_WAIT` | `90` | seconds startup waits for the underlay address before serving anyway |
| `ABE_FIO_SECONDS` | `5` | seconds of fio writes on each new volume (0: off) |
| `ABE_FIO_RAMP` | `3` | seconds of unmeasured fio warm-up before that |
| `ABE_FIO_BS` | `4k` | fio block size |
| `ABE_FIO_IODEPTH` | `1` | fio writes in flight |
| `ABE_NVMET_PATH` | `/sys/kernel/config/nvmet` | nvmet configfs root (tests only) |

Ports
-----

Every export gets its own nvmet port on `ABE_TRADDR`: the **lowest free
TCP port** in `ABE_PORT_MIN`..`ABE_PORT_MAX` (44001-44999), so the port a
delete frees is the next one handed out. Port directories in configfs
are named after the port number (`ports/44003`); ones made by older
versions (`ports/1`, `ports/2`) keep working, since only `addr_trsvcid`
is consulted. When the range is full, `/configure`, `/clone` and `/id`
answer `503` with `{"error": "no free nvmet port in 44001-44999 (N
exported)"}` and nothing is left behind. ABE does not touch the host
firewall; open 80 and 44000:44999 on the interface initiators use, e.g.
`ufw allow in on wg-flock proto tcp from 10.22.0.0/16 to any port 44000:44999`.

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
| `GET /volumes` | list every volume: `id`, `bytes`, `port` (if exported), `traddr`, `nqn`, `used_bytes`, `data_percent`, `origin`, `layers`, `warning`, `base`, `sealed`, `name` |
| `GET /clone/<id>` or `?bytes=N[&name=..]` | create a new volume as a thin snapshot of `<id>` (shares blocks until written; optionally grown to N bytes) and export it; needs `ABE_THIN_POOL`; a base must be sealed first (409); `name` works as for `/configure` |
| `GET /utilization` | thin pool (or VG) `bytes`, `used_bytes`, `free_bytes`, `data_percent`, `metadata_percent`, `provisioned_bytes`, `vg_bytes`, `vg_free_bytes`, `volumes`, `max_layers`, `warnings`, `reexport` |
| `GET /reexport` | run the startup re-export pass again; reply `{"exported","already","failed":[ids],"moved","at"}` |
| `GET /version` | `{"version", "features": [..]}`; features are `reexport`, `ports`, `name`, `trim`, and with a thin pool `base` and `clone` |

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

Replies carry `id`, `port` (nvmet trsvcid), `traddr`, `nqn` (== id) and a
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
parsing, validation). `sudo tests/e2e.sh` drives a running abe on a host
with a thin pool through every scenario, including a stop / configfs
wipe (`tests/nvmet-wipe.sh`) / start round trip. `tests/lint-links.sh`
checks the repo links.

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
