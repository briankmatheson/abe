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
| `ABE_THIN_POOL` | unset | thin pool in `ABE_VG`; volumes become thin LVs |
| `ABE_TRADDR` | `0.0.0.0` | address nvmet listens on |
| `ABE_ADVERTISE` | `ABE_TRADDR` | address reported to initiators (`traddr` in replies) |
| `ABE_LISTEN` | `0.0.0.0:80` | HTTP API address |

API
===

| Request | Effect |
|---|---|
| `GET /configure?size=5G` or `?bytes=N` | create a volume (GPT + one partition labelled with its id) and export it |
| `GET /configure?...&raw=true` | same, but leave the volume blank (VM disk images bring their own partition table) |
| `GET /id/<id>` | (re-)export an existing volume; idempotent |
| `DELETE /id/<id>` | unexport and remove the volume; idempotent |
| `GET /volumes` | list every volume: `id`, `bytes`, `port` (if exported), `traddr`, `nqn` |

Replies carry `id`, `port` (nvmet trsvcid), `traddr`, `nqn` (== id) and a
ready-to-run `nvme connect` line in `message`. Each namespace is exported
with `device_uuid` set to the volume id, so initiators get a stable
`/dev/disk/by-id/nvme-uuid.<dashed id>` path.

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
