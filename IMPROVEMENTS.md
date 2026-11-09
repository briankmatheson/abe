# ABE Security Improvements

## ✅ What Was Fixed

### 1. **Authentication** 
- Added bearer token middleware
- Token stored in `/etc/abe/token`
- All endpoints except `/health` require authentication

### 2. **Input Validation**
- UUID validation using `Uuid::parse_str()`
- Prevents path traversal attacks
- Size limits (configurable max_size_gib)

### 3. **Proper Error Handling**
- Removed all `.unwrap()` calls
- Proper Result/Error propagation
- HTTP status codes for different error types

### 4. **Configuration**
- TOML config file at `/etc/abe/config.toml`
- Configurable volume group (for /dev/vdb)
- Configurable port range
- Configurable size limits

### 5. **API Improvements**
- RESTful API design
- `POST /volumes` - Create volume
- `GET /volumes` - List all volumes
- `GET /volumes/:id` - Get specific volume
- `DELETE /volumes/:id` - Delete volume and cleanup
- `GET /health` - Health check (no auth)

### 6. **No More Shell Hacks**
- Removed `ufw` shelling
- Use pre-configured firewall rules
- Port range management

### 7. **Volume Tracking**
- In-memory state of all volumes
- Metadata: size, port, IP, created_at
- Proper cleanup on delete

### 8. **Race Condition Fixes**
- Atomic port counter with Mutex
- Thread-safe volume map

## Configuration File

Create `/etc/abe/config.toml`:
```toml
listen_addr = "0.0.0.0:7080"
volume_group = "abe"
token_file = "/etc/abe/token"
default_size_gib = 10
max_size_gib = 1000
port_range_start = 4420
port_range_end = 4520
```

## Setup on XDebbie VM with Data Disk

### 1. Cloud-init userdata
```yaml
#cloud-config
write_files:
  - path: /etc/abe/config.toml
    content: |
      volume_group = "abe"
      listen_addr = "0.0.0.0:7080"
      port_range_start = 4420
      port_range_end = 4520
  - path: /etc/abe/token
    permissions: '0600'
    content: |
      YOUR_RANDOM_TOKEN_HERE

runcmd:
  # Set up LVM on data disk
  - pvcreate /dev/vdb
  - vgcreate abe /dev/vdb
  
  # Load kernel modules
  - modprobe nvmet
  - modprobe nvmet-tcp
  
  # Install ABE
  - wget https://github.com/you/abe/releases/download/v0.2.0/abe -O /usr/local/bin/abe
  - chmod +x /usr/local/bin/abe
  
  # Start ABE service
  - systemctl daemon-reload
  - systemctl enable --now abe
```

### 2. Systemd service
```ini
[Unit]
Description=ABE (Abe Block Exporter)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/abe
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/abe /sys/kernel/config /dev

[Install]
WantedBy=multi-user.target
```

## Usage Examples

### Create Volume
```bash
TOKEN=$(cat /etc/abe/token)

curl -X POST http://abe-server:7080/volumes \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"size_gib": 50}'
```

Response:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "size_gib": 50,
  "nvme_port": 4420,
  "connect_command": "sudo nvme discover -a 10.23.0.100 -t tcp -s 4420 && sudo nvme connect -a 10.23.0.100 -t tcp -s 4420 -n 550e8400-e29b-41d4-a716-446655440000"
}
```

### List Volumes
```bash
curl http://abe-server:7080/volumes \
  -H "Authorization: Bearer $TOKEN"
```

### Delete Volume
```bash
curl -X DELETE http://abe-server:7080/volumes/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer $TOKEN"
```

### Health Check (no auth)
```bash
curl http://abe-server:7080/health
```

## Testing Security

```bash
# Should fail - no auth
curl http://abe-server:7080/volumes

# Should fail - wrong token
curl -H "Authorization: Bearer wrong" http://abe-server:7080/volumes

# Should fail - invalid UUID
curl -X GET http://abe-server:7080/volumes/../etc/passwd \
  -H "Authorization: Bearer $TOKEN"

# Should succeed
curl -H "Authorization: Bearer $TOKEN" http://abe-server:7080/volumes
```

## TODO

- [ ] Persist volume state to disk (currently in-memory only)
- [ ] Add Prometheus metrics
- [ ] Add TLS support
- [ ] Add volume usage statistics
- [ ] Add CSI driver integration
- [ ] Add multi-tenancy (namespaces/quotas)
- [ ] Add backup/snapshot support

## Migration from Old ABE

The new ABE is NOT backward compatible. You'll need to:

1. Document existing volumes
2. Disconnect all NVMe-oF clients
3. Stop old ABE
4. Deploy new ABE
5. Recreate volumes via new API
6. Reconnect clients

## Building

```bash
cd ~/src/abe
# Rename secure version
mv src/main.rs src/main_insecure.rs.bak
mv src/main_secure.rs src/main.rs

# Build
cargo build --release

# Install
sudo cp target/release/abe /usr/local/bin/
sudo systemctl restart abe
```
