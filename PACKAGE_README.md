# ABE Debian Package

## 📦 Package Built

**File:** `target/debian/abe-block-exporter_0.5.0-1_amd64.deb`  
**Package:** `abe-block-exporter` (the binary, unit and defaults keep the short name `abe`)  
**Version:** 0.5.0-1

## Security

The API is HTTPS with mutual TLS (clients need a certificate signed by
`ABE_TLS_CA`), and every nvmet port is fenced with nftables to the
address that asked for it. See `README.md` (sections "TLS" and "Port
fence") and `SECURITY_AUDIT.md`.

## Installation

```bash
sudo dpkg -i target/debian/abe-block-exporter_0.5.0-1_amd64.deb
```

## Setup

### 1. Create LVM Volume Group

On hypervisor with data disk (`/dev/vdb`):
```bash
sudo pvcreate /dev/vdb
sudo vgcreate abe /dev/vdb
```

Or use XDebbie VM with `dataDiskGib` set.

### 2. Certificates

Put the server certificate, its key and the client CA at
`/etc/abe/{cert,key,ca}.pem` (or set `ABE_TLS_CERT` / `ABE_TLS_KEY` /
`ABE_TLS_CA` in `/etc/default/abe`). `README.md`, section "TLS", has the
openssl commands for a standalone CA. If the host firewall filters
input, let 443 and the nvmet range 44001:44999 through on the interface
initiators use; abe's own table (`inet abe`) narrows each port to the
client that asked for it.

### 3. Start ABE

```bash
sudo systemctl start abe
sudo systemctl status abe
```

## Usage

### Create Volume

```bash
# Configure creates a 10G volume (see README.md for ?bytes=, ?name=, ...)
CURL="curl --cacert ca.pem --cert client.pem --key client-key.pem"
$CURL https://abe-server/configure
```

Response (abridged):
```json
{
  "message": "sudo nvme connect -a 10.23.0.100 -t tcp -s 44001 -n 550e8400e29b41d4a716446655440000",
  "id": "550e8400e29b41d4a716446655440000",
  "port": "44001",
  "client": "10.23.0.7"
}
```

The port is open only to `client`, the address the request came from.

### Attach Existing Volume

```bash
$CURL https://abe-server/id/{uuid}
```

## Integration with XDebbie

Create ABE VM via CAPX:

```yaml
apiVersion: infrastructure.cluster.x-k8s.io/v1alpha1
kind: XDebbie8sMachineTemplate
metadata:
  name: abe-server-mt
spec:
  template:
    spec:
      memoryMib: 4096
      vcpus: 2
      diskGib: 20
      dataDiskGib: 500  # 500GB data disk for volumes
      image: debian-12-base
```

Cloud-init userdata:
```yaml
#cloud-config
packages:
  - lvm2

runcmd:
  # Setup LVM on data disk
  - pvcreate /dev/vdb
  - vgcreate abe /dev/vdb
  
  # Install ABE
  - wget https://path/to/abe-block-exporter_0.5.0-1_amd64.deb
  - dpkg -i abe-block-exporter_0.5.0-1_amd64.deb
  
  # Start ABE
  - systemctl start abe
```

## Files Installed

- `/usr/bin/abe` - Main binary
- `/lib/systemd/system/abe.service` - Systemd service
- `/etc/modules-load.d/abe.conf` - Kernel modules
- `/usr/share/doc/abe/SECURITY_AUDIT.md` - Security documentation

## Kernel Modules

ABE automatically loads:
- `nvmet` - NVMe-oF target subsystem
- `nvmet-tcp` - NVMe over TCP transport

## Uninstall

```bash
sudo systemctl stop abe
sudo dpkg -r abe-block-exporter
```

**Note:** LVM volumes are NOT automatically deleted. Clean up manually:
```bash
sudo lvremove /dev/abe/*
sudo vgremove abe
sudo pvremove /dev/vdb
```
