# ABE Debian Package

## 📦 Package Built

**File:** `/home/bmath/src/abe/target/debian/abe_0.1.0-1_amd64.deb`  
**Size:** 811 KB  
**Version:** 0.1.0-1

## ⚠️ Security Warning

**This package contains the INSECURE version of ABE without authentication!**

- Use ONLY in isolated/trusted networks
- See `SECURITY_AUDIT.md` for detailed security issues
- Secure version (`main_secure_v1.rs.bak`) needs axum middleware fixes

## Installation

```bash
sudo dpkg -i ~/src/abe/target/debian/abe_0.1.0-1_amd64.deb
```

## Setup

### 1. Create LVM Volume Group

On hypervisor with data disk (`/dev/vdb`):
```bash
sudo pvcreate /dev/vdb
sudo vgcreate abe /dev/vdb
```

Or use XDebbie VM with `dataDiskGib` set.

### 2. Configure Firewall (IMPORTANT!)

```bash
# Allow only from internal network
sudo ufw allow from 10.0.0.0/8 to any port 80

# Or use specific port range for NVMe-oF
sudo ufw allow 4000:5000/tcp
```

### 3. Start ABE

```bash
sudo systemctl start abe
sudo systemctl status abe
```

## Usage

### Create Volume

```bash
# Configure creates 10GB volume
curl http://abe-server/configure
```

Response:
```json
{
  "message": "sudo nvme discover -a 10.23.0.100 -t tcp -s 4001 ; sudo nvme connect -a 10.23.0.100 -t tcp -s 4001 -n 550e8400e29b41d4a716446655440000",
  "id": "550e8400e29b41d4a716446655440000",
  "port": "4001"
}
```

### Attach Existing Volume

```bash
curl http://abe-server/id/{uuid}
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
  - wget https://path/to/abe_0.1.0-1_amd64.deb
  - dpkg -i abe_0.1.0-1_amd64.deb
  
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

## TODO: Secure Version

The secure version with authentication exists but needs axum 0.7 middleware fixes:

1. Fix middleware signature for axum 0.7
2. Add bearer token authentication
3. Add proper REST API (POST/DELETE /volumes)
4. Add volume tracking
5. Add configuration file support

See `src/main_secure_v1.rs.bak` for implementation.

## Uninstall

```bash
sudo systemctl stop abe
sudo dpkg -r abe
```

**Note:** LVM volumes are NOT automatically deleted. Clean up manually:
```bash
sudo lvremove /dev/abe/*
sudo vgremove abe
sudo pvremove /dev/vdb
```
