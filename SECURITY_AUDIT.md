# ABE Security Audit

## 🔴 CRITICAL Issues

### 1. **No Authentication** (CRITICAL)
- **Line 260-270**: HTTP server on port 80 with NO authentication
- **Risk**: Anyone on the network can create volumes and consume storage
- **Fix**: Add bearer token authentication

### 2. **Command Injection via UUID** (CRITICAL)
- **Line 48**: `id` from URL path is used directly in commands
- **Lines 238-246**: UUID passed to `parted` and `lvcreate` without validation
- **Risk**: Path traversal, command injection
```rust
// VULNERABLE:
async fn attach(EP(id): EP<String>) -> Json<Message>
create_lv(&id, VOL_SIZE);  // id could be "../../../etc/passwd"
```
- **Fix**: Validate UUID format strictly

### 3. **Arbitrary Firewall Rules** (HIGH)
- **Line 84**: Automatically opens firewall ports via `ufw allow`
- **Risk**: Port exhaustion, firewall policy bypass
- **Fix**: Pre-configure firewall ranges, don't shell out

### 4. **Hardcoded Volume Group** (MEDIUM)
- **Line 231**: Hardcoded `"abe"` volume group name
- **Risk**: Inflexible, won't work with `/dev/vdb` setup
- **Fix**: Make VG configurable

### 5. **No Input Validation** (HIGH)
- Volume size hardcoded to `10G`
- No validation of NVMe-oF parameters
- No checks on available storage

### 6. **Excessive .unwrap() Calls** (MEDIUM)
- **Lines 51, 60, 66, 82, 86**: Will panic on errors
- **Risk**: DoS via malformed requests
- **Fix**: Proper error handling

### 7. **Race Conditions** (MEDIUM)
- **Line 51-60**: Port number calculation has TOCTOU race
- Multiple requests can get same port number
- **Fix**: Use atomic counters or mutex

## 🟡 DESIGN Issues

### 8. **Listening on 0.0.0.0:80** (MEDIUM)
- Binds to all interfaces
- Should listen on specific interface or localhost only

### 9. **No TLS** (HIGH)
- All traffic in plaintext
- Credentials (if added) would be sniffable

### 10. **No Volume Lifecycle Management**
- No way to list volumes
- No way to delete volumes
- No way to see usage/capacity

### 11. **No Metrics/Monitoring**
- No Prometheus metrics
- No health checks
- No logging of who created what

## 🔧 Recommended Fixes

### Phase 1: Critical Security
```rust
// Add authentication middleware
use axum::http::{Request, StatusCode};
use axum::middleware::Next;

async fn auth<B>(
    req: Request<B>,
    next: Next<B>,
) -> Result<Response, StatusCode> {
    let token = req.headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    
    let expected = std::fs::read_to_string("/etc/abe/token")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    if token != expected.trim() {
        return Err(StatusCode::FORBIDDEN);
    }
    
    Ok(next.run(req).await)
}

// Validate UUID
fn validate_uuid(id: &str) -> Result<Uuid, Error> {
    Uuid::parse_str(id)
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid UUID"))
}

// Use in endpoints:
async fn attach(EP(id): EP<String>) -> Result<Json<Message>, StatusCode> {
    let uuid = validate_uuid(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
    // ...
}
```

### Phase 2: Configuration
```rust
#[derive(Deserialize)]
struct Config {
    listen_addr: String,
    volume_group: String,
    token_file: String,
    default_size_gib: u64,
    max_size_gib: u64,
    port_range_start: u16,
    port_range_end: u16,
}
```

### Phase 3: Proper API
```toml
# Add these routes:
POST   /volumes          # Create volume with size
GET    /volumes          # List all volumes
GET    /volumes/:id      # Get volume details
DELETE /volumes/:id      # Delete volume and cleanup NVMe-oF
GET    /health           # Health check
GET    /metrics          # Prometheus metrics
```

### Phase 4: Data Disk Integration
```rust
// Auto-detect /dev/vdb and set up LVM
fn setup_data_disk() -> Result<()> {
    if Path::new("/dev/vdb").exists() {
        // Create PV
        Command::new("pvcreate")
            .arg("/dev/vdb")
            .output()?;
        
        // Create VG
        Command::new("vgcreate")
            .args(["abe", "/dev/vdb"])
            .output()?;
    }
    Ok(())
}
```

## Priority Fix Order

1. ✅ **Add UUID validation** (prevents injection)
2. ✅ **Add bearer token auth** (prevents unauthorized access)
3. ✅ **Remove ufw shelling** (use pre-configured firewall)
4. ✅ **Add proper error handling** (remove unwrap())
5. ✅ **Make VG configurable** (support /dev/vdb)
6. ⚠️ **Add TLS support** (encrypt traffic)
7. ⚠️ **Add DELETE endpoint** (cleanup)
8. ⚠️ **Add metrics** (observability)

## Testing Security

```bash
# Test without auth (should fail)
curl http://abe-server/configure

# Test with invalid UUID (should fail)
curl -H "Authorization: Bearer token" \
     http://abe-server/id/../../../etc/passwd

# Test with valid request
curl -H "Authorization: Bearer $(cat /etc/abe/token)" \
     http://abe-server/configure
```
