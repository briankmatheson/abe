use axum::{
    extract::{ConnectInfo, Path as EP, Query},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use if_addrs::get_if_addrs;
use log::{error, info, warn};
use nix::mount::{mount, MsFlags};
use nix::unistd::symlinkat;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::env::var;
use std::fmt::Display;
use std::fs::{self, write, File};
use std::io::{BufReader, Error, ErrorKind, Result, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str;
use std::sync::{Arc, Mutex};
use uuid::Uuid;
//use env_inventory;

const CONFIGFS_PATH: &str = "/sys/kernel/config";

/// Root of the nvmet configfs tree (ABE_NVMET_PATH, default
/// /sys/kernel/config/nvmet). Overridable so the port scan can be tested
/// against a plain directory.
fn nvmet_path() -> String {
    var("ABE_NVMET_PATH")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/sys/kernel/config/nvmet".to_string())
}

/// One process-wide lock around everything that changes LVM or configfs:
/// LV create/partition/tag, export, unexport, lvremove, clone, seal and the
/// startup re-export pass. fio and the trim after it run outside it (only
/// the creating request knows the new id, so nobody else can touch the
/// volume), and read-only handlers never take it.
static OPS: Mutex<()> = Mutex::new(());

/// Run `f` while holding OPS. A poisoned lock (a panic inside an earlier
/// holder) is taken over rather than propagated: the LVM/configfs state is
/// authoritative, not whatever the panicking request had in memory.
fn with_ops<T, E>(f: impl FnOnce() -> std::result::Result<T, E>) -> std::result::Result<T, E> {
    let _g = OPS.lock().unwrap_or_else(|e| e.into_inner());
    f()
}

/// Volume group the LVs live in. Override with ABE_VG.
fn vg_name() -> String {
    var("ABE_VG").unwrap_or_else(|_| "abe".to_string())
}

/// Thin pool inside the VG; when set, volumes are thin LVs
/// (`lvcreate -V size -T vg/pool`) instead of thick ones. ABE_THIN_POOL.
fn thin_pool() -> Option<String> {
    var("ABE_THIN_POOL").ok().filter(|s| !s.is_empty())
}

/// Address nvmet listens on (ABE_TRADDR, default every interface).
fn bind_traddr() -> String {
    var("ABE_TRADDR").unwrap_or_else(|_| "0.0.0.0".to_string())
}

/// Address initiators should connect to (ABE_ADVERTISE). Defaults to the
/// bind address, which is useless when that is 0.0.0.0, so set it when
/// clients are on another box.
fn advertised_traddr() -> String {
    var("ABE_ADVERTISE")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(bind_traddr)
}

/// API listen address (ABE_LISTEN, default 0.0.0.0:443).
fn listen_addr() -> String {
    var("ABE_LISTEN").unwrap_or_else(|_| "0.0.0.0:443".to_string())
}

/// Is the API served over mutual TLS? ABE_TLS, default on; `off` means
/// plain HTTP (the unprivileged test harness, standalone experiments).
fn tls_enabled() -> bool {
    var("ABE_TLS").map(|v| v.trim() != "off").unwrap_or(true)
}

/// A PEM path from the environment, with its default under /etc/abe.
fn tls_path(key: &str, default: &str) -> PathBuf {
    PathBuf::from(
        var(key)
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| default.to_string()),
    )
}

/// (server cert, private key, client CA bundle): ABE_TLS_CERT,
/// ABE_TLS_KEY and ABE_TLS_CA, default /etc/abe/{cert,key,ca}.pem.
fn tls_paths() -> (PathBuf, PathBuf, PathBuf) {
    (
        tls_path("ABE_TLS_CERT", "/etc/abe/cert.pem"),
        tls_path("ABE_TLS_KEY", "/etc/abe/key.pem"),
        tls_path("ABE_TLS_CA", "/etc/abe/ca.pem"),
    )
}

/// rustls wants one process-wide crypto provider; pick it once. Harmless
/// if it was already installed (tests build several configs).
fn ensure_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Every certificate in the PEM file at `path`; an error names the path.
fn read_pem_certs(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let at = |e: Error| Error::new(e.kind(), format!("{}: {e}", path.display()));
    let mut r = BufReader::new(File::open(path).map_err(at)?);
    let certs: Vec<_> = rustls_pemfile::certs(&mut r)
        .collect::<Result<_>>()
        .map_err(at)?;
    if certs.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("{}: no certificate in it", path.display()),
        ));
    }
    Ok(certs)
}

/// The first private key (PKCS#8, RSA or EC PEM) in the file at `path`.
fn read_pem_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let at = |e: Error| Error::new(e.kind(), format!("{}: {e}", path.display()));
    let mut r = BufReader::new(File::open(path).map_err(at)?);
    rustls_pemfile::private_key(&mut r)
        .map_err(at)?
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                format!("{}: no private key in it", path.display()),
            )
        })
}

/// A verifier that accepts only client certificates chaining to the CAs
/// in `ca` (no unauthenticated clients).
fn client_verifier(ca: &Path) -> Result<Arc<dyn rustls::server::danger::ClientCertVerifier>> {
    ensure_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    for c in read_pem_certs(ca)? {
        roots.add(c).map_err(|e| {
            Error::new(
                ErrorKind::InvalidData,
                format!("{}: not a CA certificate: {e}", ca.display()),
            )
        })?;
    }
    rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| Error::other(format!("{}: client verifier: {e}", ca.display())))
}

/// Mutual-TLS server config: our `cert`+`key`, clients must chain to `ca`.
fn tls_config_from(cert: &Path, key: &Path, ca: &Path) -> Result<Arc<rustls::ServerConfig>> {
    let verifier = client_verifier(ca)?;
    let chain = read_pem_certs(cert)?;
    let key_der = read_pem_key(key)?;
    let cfg = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key_der)
        .map_err(|e| Error::other(format!("{} / {}: {e}", cert.display(), key.display())))?;
    Ok(Arc::new(cfg))
}

/// The server config from ABE_TLS_CERT / ABE_TLS_KEY / ABE_TLS_CA.
fn tls_config() -> Result<Arc<rustls::ServerConfig>> {
    let (cert, key, ca) = tls_paths();
    tls_config_from(&cert, &key, &ca)
}

// ---- the nvmet fence ---------------------------------------------------
//
// nvmet has no per-client authentication worth the name, so abe keeps an
// nftables table of its own: a set of (client ip, port) pairs and a chain
// that resets every other connection to the port range. A port is opened
// to the address the API call came from (the TLS peer), never to a
// parameter, so reaching a volume needs a cert *and* that address.

/// The nft binary: ABE_NFT, else `nft` on PATH, else /usr/sbin/nft.
fn nft_bin() -> PathBuf {
    if let Some(p) = var("ABE_NFT").ok().filter(|s| !s.is_empty()) {
        return PathBuf::from(p);
    }
    if let Ok(path) = var("PATH") {
        for d in path.split(':').filter(|d| !d.is_empty()) {
            let p = Path::new(d).join("nft");
            if p.is_file() {
                return p;
            }
        }
    }
    PathBuf::from("/usr/sbin/nft")
}

/// Run nft with `args` (and `script` on stdin); its stdout. The error
/// carries nft's stderr.
fn nft(args: &[&str], script: Option<&str>) -> Result<String> {
    use std::process::Stdio;
    let bin = nft_bin();
    let mut cmd = Command::new(&bin);
    cmd.args(args)
        .stdin(if script.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| Error::new(e.kind(), format!("{}: {e}", bin.display())))?;
    if let Some(text) = script {
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(text.as_bytes())?;
        }
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(Error::other(format!(
            "nft {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

const RESERVED_PORTS: &str = "/proc/sys/net/ipv4/ip_local_reserved_ports";

/// Keep the kernel from using `min..=max` as ephemeral source ports
/// (`net.ipv4.ip_local_reserved_ports`): a local initiator whose source
/// port landed on an nvmet port would collide with a later export (the
/// `EADDRNOTAVAIL` that re-export retries around) and, before the fence
/// learnt to judge SYNs only, had its SYN-ACK reset. Appends to whatever
/// is already reserved; the kernel merges overlapping ranges. Best effort:
/// a failure is logged, not fatal.
fn reserve_ports(path: &Path, min: u16, max: u16) {
    let want = format!("{min}-{max}");
    let have = fs::read_to_string(path).unwrap_or_default();
    match reserved_ports_update(have.trim(), min, max) {
        None => info!("ports {want} already reserved from ephemeral use"),
        Some(new) => match fs::write(path, &new) {
            Ok(()) => info!("reserved ports {want} from ephemeral use ({})", path.display()),
            Err(e) => warn!(
                "could not reserve ports {want} from ephemeral use ({}): {e}; local initiators may collide with exports",
                path.display()
            ),
        },
    }
}

/// The new `ip_local_reserved_ports` value if `min..=max` is not already
/// covered by one of `have`'s comma-separated entries (`n` or `a-b`).
fn reserved_ports_update(have: &str, min: u16, max: u16) -> Option<String> {
    let covered = have.split(',').map(str::trim).any(|e| {
        let (a, b) = match e.split_once('-') {
            Some((a, b)) => (a.parse::<u16>().ok(), b.parse::<u16>().ok()),
            None => (e.parse::<u16>().ok(), e.parse::<u16>().ok()),
        };
        matches!((a, b), (Some(a), Some(b)) if a <= min && b >= max)
    });
    if covered {
        return None;
    }
    let want = format!("{min}-{max}");
    Some(if have.is_empty() {
        want
    } else {
        format!("{have},{want}")
    })
}

/// The whole `inet abe` table as one `nft -f` transaction: `ports` holds
/// every exported nvmet port, `allowed` the `(client, port)` pairs, and
/// a SYN to an exported port from anyone but its client is reset. The
/// configured range plays no part here, so an export that survived a
/// range change stays fenced. `destroy` (nft >= 1.0.7) so a missing
/// table is not an error. `accept` only ends this chain: other base
/// chains on input still run.
///
/// Only a bare SYN (a new connection attempt) is ever rejected. For a
/// local initiator both directions of a connection pass the input hook,
/// and its ephemeral source port could land on an exported port, so
/// without the flags test the SYN-ACK back to it (dport = that port,
/// not in `allowed`) would be reset and the connect would time out.
/// `reserve_ports` keeps the kernel from handing out the range too.
fn fence_script(ports: &[u16], elements: &[(Ipv4Addr, u16)]) -> String {
    let set = |items: Vec<String>| {
        if items.is_empty() {
            String::new()
        } else {
            format!("        elements = {{ {} }}", items.join(", "))
        }
    };
    let ports = set(ports.iter().map(|p| p.to_string()).collect());
    let elems = set(elements
        .iter()
        .map(|(ip, port)| format!("{ip} . {port}"))
        .collect());
    [
        "destroy table inet abe".to_string(),
        "table inet abe {".to_string(),
        "    set ports {".to_string(),
        "        type inet_service".to_string(),
        "        comment \"nvmet ports exported by abe\"".to_string(),
        ports,
        "    }".to_string(),
        "    set allowed {".to_string(),
        "        type ipv4_addr . inet_service".to_string(),
        "        comment \"client ip . nvmet port opened by abe\"".to_string(),
        elems,
        "    }".to_string(),
        "    chain input {".to_string(),
        "        type filter hook input priority filter - 10; policy accept;".to_string(),
        "        ip saddr . tcp dport @allowed  accept".to_string(),
        "        tcp dport @ports  tcp flags & (syn | ack) == syn  reject with tcp reset".to_string(),
        "        meta nfproto ipv6  tcp dport @ports  tcp flags & (syn | ack) == syn  reject with tcp reset"
            .to_string(),
        "    }".to_string(),
        "}".to_string(),
    ]
    .into_iter()
    .filter(|l| !l.is_empty())
    .map(|l| l + "\n")
    .collect()
}

/// The table with empty sets.
#[cfg(test)]
fn fence_script_empty() -> String {
    fence_script(&[], &[])
}

/// Replace the `inet abe` table atomically with one that fences exactly
/// `ports` and allows exactly `elements`. Under OPS when exports exist.
fn fence_install(ports: &[u16], elements: &[(Ipv4Addr, u16)]) -> Result<()> {
    nft(&["-f", "-"], Some(&fence_script(ports, elements)))?;
    info!(
        "fence: table inet abe installed with {} exported port(s), {} open",
        ports.len(),
        elements.len()
    );
    Ok(())
}

/// Under OPS: `port` is reachable from `ip` and nobody else.
fn fence_open(ip: Ipv4Addr, port: u16) -> Result<()> {
    fence_close_port(port)?;
    nft(
        &[
            "add",
            "element",
            "inet",
            "abe",
            "allowed",
            &format!("{{ {ip} . {port} }}"),
        ],
        None,
    )?;
    info!("fence: opened {port} to {ip}");
    Ok(())
}

/// `port` is in the `ports` set (rejecting everyone not in `allowed`).
/// Adding an element that is already there is not an error.
fn fence_mark_exported(port: u16) -> Result<()> {
    nft(
        &[
            "add",
            "element",
            "inet",
            "abe",
            "ports",
            &format!("{{ {port} }}"),
        ],
        None,
    )
    .map(drop)
}

/// Under OPS: `port` is no longer exported; drop it from both sets.
fn fence_forget_port(port: u16) -> Result<()> {
    fence_close_port(port)?;
    match nft(
        &[
            "delete",
            "element",
            "inet",
            "abe",
            "ports",
            &format!("{{ {port} }}"),
        ],
        None,
    ) {
        Ok(_) => Ok(()),
        // not in the set, or no table: nothing to forget
        Err(e) if e.to_string().contains("No such file or directory") => Ok(()),
        Err(e) => Err(e),
    }
}

/// Under OPS: `port` rejects everyone — it is in `ports` and every
/// `allowed` element for it is dropped. A port that was not open is not
/// an error; no table at all is a warning (GET /reexport rebuilds it).
fn fence_close_port(port: u16) -> Result<()> {
    let open = match nft(&["-j", "list", "set", "inet", "abe", "allowed"], None) {
        Ok(json) => parse_nft_set_json(&json)?,
        Err(e) if e.to_string().contains("No such file or directory") => {
            warn!("fence: no table inet abe while closing {port} (GET /reexport rebuilds it)");
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    fence_mark_exported(port)?;
    for (p, ip) in open {
        if p != port {
            continue;
        }
        info!("closing {port} (was open to {ip})");
        nft(
            &[
                "delete",
                "element",
                "inet",
                "abe",
                "allowed",
                &format!("{{ {ip} . {port} }}"),
            ],
            None,
        )?;
    }
    Ok(())
}

/// What the fence allows right now: port -> client.
fn fence_list() -> Result<BTreeMap<u16, Ipv4Addr>> {
    let json = nft(&["-j", "list", "set", "inet", "abe", "allowed"], None)?;
    parse_nft_set_json(&json)
}

/// The `(ip, port)` elements in `nft -j list set inet abe allowed`.
fn parse_nft_set_json(json: &str) -> Result<BTreeMap<u16, Ipv4Addr>> {
    let v: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| Error::new(ErrorKind::InvalidData, format!("nft -j: {e}")))?;
    let mut map = BTreeMap::new();
    let Some(objs) = v.get("nftables").and_then(|n| n.as_array()) else {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "nft -j: no nftables array",
        ));
    };
    for set in objs.iter().filter_map(|o| o.get("set")) {
        let Some(elems) = set.get("elem").and_then(|e| e.as_array()) else {
            continue;
        };
        for e in elems {
            let Some(c) = e.get("concat").and_then(|c| c.as_array()) else {
                continue;
            };
            let ip = c
                .first()
                .and_then(|x| x.as_str())
                .and_then(|x| x.parse().ok());
            let port = c
                .get(1)
                .and_then(|x| x.as_u64())
                .and_then(|x| u16::try_from(x).ok());
            if let (Some(ip), Some(port)) = (ip, port) {
                map.insert(port, ip);
            }
        }
    }
    Ok(map)
}

/// The distinct remote addresses with an established TCP connection to
/// local `port`, from a `/proc/net/tcp` body. Addresses there are hex in
/// host byte order (little-endian on x86: 0100007F is 127.0.0.1).
fn peers_on_port(proc_net_tcp: &str, port: u16) -> BTreeSet<Ipv4Addr> {
    let mut peers = BTreeSet::new();
    for line in proc_net_tcp.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 || f[3] != "01" {
            continue;
        }
        let (Some((_, lport)), Some((rip, _))) = (f[1].split_once(':'), f[2].split_once(':'))
        else {
            continue;
        };
        if u16::from_str_radix(lport, 16).ok() != Some(port) {
            continue;
        }
        if let Ok(raw) = u32::from_str_radix(rip, 16) {
            peers.insert(Ipv4Addr::from(raw.swap_bytes()));
        }
    }
    peers
}

/// Who is connected to `port` right now.
fn established_peers(port: u16) -> BTreeSet<Ipv4Addr> {
    match fs::read_to_string("/proc/net/tcp") {
        Ok(t) => peers_on_port(&t, port),
        Err(e) => {
            warn!("/proc/net/tcp: {e}");
            BTreeSet::new()
        }
    }
}

/// Volume ids are v4 UUIDs without dashes; nvmet wants the dashed form for
/// device_uuid, which is what gives initiators /dev/disk/by-id/nvme-uuid.<id>.
fn dashed_uuid(id: &str) -> Option<String> {
    Uuid::parse_str(id).ok().map(|u| u.hyphenated().to_string())
}
/// Default LV size when /configure is called without ?size=. Override with
/// ABE_VOL_SIZE. Accepts anything lvcreate -L does (e.g. "10G", "512M").
fn default_vol_size() -> String {
    var("ABE_VOL_SIZE").unwrap_or_else(|_| "10G".to_string())
}

fn new_id() -> String {
    Uuid::new_v4().to_string().replace("-", "")
}

/// Size of the LV called `id`, if it exists.
fn lv_bytes(id: &str) -> Option<u64> {
    list_lvs()
        .ok()?
        .into_iter()
        .find(|l| l.name == id)
        .map(|l| l.bytes)
}

/// Convert a byte count (e.g. a CSI capacity) to an lvcreate -L size,
/// rounded up to a whole MiB.
fn bytes_to_lv_size(bytes: u64) -> String {
    let mib = (bytes + (1 << 20) - 1) >> 20;
    format!("{}M", mib.max(4))
}

#[derive(Deserialize, Default)]
struct ConfigureParams {
    /// lvcreate size string, e.g. "5G"
    size: Option<String>,
    /// or a raw byte count (takes precedence)
    bytes: Option<u64>,
    /// leave the volume blank instead of writing a GPT with one partition
    /// (VM disk images bring their own partition table)
    raw: Option<bool>,
    /// idempotency key: if a volume tagged `abe_name=<name>` exists it is
    /// returned (with `existing: true`) instead of a new one being made
    name: Option<String>,
    /// make (or return) the base volume for this image: raw, no fio,
    /// one per image; see /seal
    base: Option<String>,
}

type ApiError = (StatusCode, Json<ErrorMessage>);

#[derive(Serialize)]
struct ErrorMessage {
    error: String,
}

fn api_err<E: Display>(what: &str, e: E) -> ApiError {
    let msg = format!("{what}: {e}");
    warn!("{msg}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorMessage { error: msg }),
    )
}

/// An error from the blocking side of a handler, with the HTTP status it
/// should turn into. Plain io errors become 500s.
#[derive(Debug)]
struct Fail {
    status: StatusCode,
    error: String,
}

type Res<T> = std::result::Result<T, Fail>;

impl Fail {
    fn new(status: StatusCode, error: impl Into<String>) -> Self {
        Fail {
            status,
            error: error.into(),
        }
    }
    fn bad_request(error: impl Into<String>) -> Self {
        Fail::new(StatusCode::BAD_REQUEST, error)
    }
    fn not_found(id: &str) -> Self {
        Fail::new(StatusCode::NOT_FOUND, format!("no volume {id}"))
    }
    fn conflict(error: impl Into<String>) -> Self {
        Fail::new(StatusCode::CONFLICT, error)
    }
    /// `.map_err(Fail::ctx("lvremove"))`: a 500 that says which step failed.
    fn ctx(what: &'static str) -> impl FnOnce(Error) -> Fail {
        move |e| Fail::new(StatusCode::INTERNAL_SERVER_ERROR, format!("{what}: {e}"))
    }
    fn into_api(self) -> ApiError {
        if self.status.is_server_error() {
            warn!("{}", self.error);
        } else {
            info!("{} -> {}", self.error, self.status.as_u16());
        }
        (self.status, Json(ErrorMessage { error: self.error }))
    }
}

impl From<Error> for Fail {
    fn from(e: Error) -> Self {
        Fail::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    }
}

/// The IPv4 address a request came from: what its port is fenced to. A
/// v4-mapped v6 peer (a dual-stack listener) is unmapped; anything else
/// is a 400, since the fence is IPv4-only.
fn client_ip(peer: SocketAddr) -> Res<Ipv4Addr> {
    match peer.ip() {
        std::net::IpAddr::V4(a) => Ok(a),
        std::net::IpAddr::V6(a) => a.to_ipv4_mapped().ok_or_else(|| {
            Fail::bad_request(format!(
                "fence needs an IPv4 client address (request came from {a})"
            ))
        }),
    }
}

/// Run the blocking part of a handler on the blocking pool.
async fn run_blocking<T: Send + 'static>(
    f: impl FnOnce() -> Res<T> + Send + 'static,
) -> std::result::Result<T, ApiError> {
    match tokio::task::spawn_blocking(f).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(f)) => Err(f.into_api()),
        Err(e) => Err(api_err("blocking task", e)),
    }
}

//env_inventory::register!(RUST_LOG = "info")

#[derive(Serialize, Deserialize)]
struct Message {
    message: String,
    id: String,
    port: String,
    /// address initiators connect to (ABE_ADVERTISE)
    traddr: String,
    /// NVMe qualified name of the subsystem (== id)
    nqn: String,
    /// size of the LV (what `?bytes=`/`?size=` produced, rounded up to a MiB)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bytes: Option<u64>,
    /// what fio measured on a freshly created volume (/configure only)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    perf: Option<Perf>,
    /// true when `?name=` or `?base=` matched a volume that already existed
    #[serde(default)]
    existing: bool,
    /// base volumes only: the image this is the base for
    #[serde(default, skip_serializing_if = "Option::is_none")]
    base: Option<String>,
    /// base volumes only: sealed bases are never exported (`port` is empty)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sealed: Option<bool>,
    /// the address the port is fenced to: the caller's own
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client: Option<String>,
}

/// Reply of GET /seal/<id>.
#[derive(Serialize)]
struct SealReply {
    id: String,
    base: String,
    sealed: bool,
    bytes: u64,
}

/// Reply of GET /version.
#[derive(Serialize)]
struct Version {
    version: &'static str,
    /// what this abe can do, for callers that must also work with older
    /// ones: reexport, ports, name, trim, tls, fence, and (with a thin
    /// pool) base, clone
    features: Vec<&'static str>,
    /// the API is served over mutual TLS (ABE_TLS)
    tls: bool,
}

impl Message {
    /// The reply for `id` exported on `port`.
    fn exported(id: &str, port: &str) -> Message {
        let traddr = advertised_traddr();
        Message {
            message: format!("sudo nvme connect -a {traddr} -t tcp -s {port} -n {id}"),
            id: id.to_string(),
            port: port.to_string(),
            traddr,
            nqn: id.to_string(),
            bytes: lv_bytes(id),
            perf: None,
            existing: false,
            base: None,
            sealed: None,
            client: None,
        }
    }

    /// The reply for a sealed base: nothing to connect to.
    fn sealed_base(lv: &Lv, image: &str) -> Message {
        Message {
            message: format!("{} is a sealed base; clone it", lv.name),
            id: lv.name.clone(),
            port: String::new(),
            traddr: advertised_traddr(),
            nqn: lv.name.clone(),
            bytes: Some(lv.bytes),
            perf: None,
            existing: true,
            base: Some(image.to_string()),
            sealed: Some(true),
            client: None,
        }
    }
}

/// A short fio run on a new volume before it is handed out: random
/// direct writes at ABE_FIO_BS (4k) with ABE_FIO_IODEPTH (1) in flight,
/// so write_lat_us is what one synchronous small write costs on this pool
/// right now.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct Perf {
    bs: String,
    iodepth: u32,
    seconds: f64,
    write_mib_s: f64,
    write_iops: f64,
    /// mean completion latency
    write_lat_us: f64,
    /// the region fio wrote was discarded (thin: given back to the pool)
    /// or zeroed (thick) afterwards; false if that failed
    #[serde(default)]
    trimmed: bool,
}

/// How long fio writes to each new volume (ABE_FIO_SECONDS, default 5;
/// 0 disables), after how long a warm-up that is not measured
/// (ABE_FIO_RAMP, default 3), with what block size (ABE_FIO_BS, default
/// 4k) and how many in flight (ABE_FIO_IODEPTH, default 1).
fn fio_seconds() -> u64 {
    var("ABE_FIO_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5)
}
fn fio_bs() -> String {
    var("ABE_FIO_BS")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "4k".to_string())
}
fn fio_ramp() -> u64 {
    var("ABE_FIO_RAMP")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3)
}
fn fio_iodepth() -> u32 {
    var("ABE_FIO_IODEPTH")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&d| d > 0)
        .unwrap_or(1)
}

/// One entry of GET /volumes.
#[derive(Serialize)]
struct Volume {
    id: String,
    bytes: u64,
    /// trsvcid if currently exported
    port: Option<String>,
    traddr: String,
    nqn: String,
    /// bytes actually allocated: `bytes * data_percent` for a thin volume
    /// (unknown while it is inactive), all of it for a thick one
    used_bytes: Option<u64>,
    /// thin volumes only: how much of `bytes` is allocated
    data_percent: Option<f64>,
    /// the volume this one was cloned from, while that volume still exists
    origin: Option<String>,
    /// snapshot layers under this volume: 0 for a plain volume, 1 for a
    /// clone, 2 for a clone of a clone, ...
    layers: u32,
    /// set when `layers` is over MAX_SNAPSHOT_LAYERS
    #[serde(skip_serializing_if = "Option::is_none")]
    warning: Option<String>,
    /// the image this volume is the base for (`abe_base` tag)
    base: Option<String>,
    /// a sealed base: never exported, clone-only
    sealed: bool,
    /// the caller's name for it (`abe_name` tag)
    name: Option<String>,
    /// while exported: the address the fence opens its port to
    client: Option<String>,
}

/// More snapshot layers than this under one volume earns a warning.
const MAX_SNAPSHOT_LAYERS: u32 = 10;

#[derive(Deserialize, Default)]
struct CloneParams {
    /// size of the clone; defaults to the origin's, and cannot be smaller
    bytes: Option<u64>,
    /// idempotency key, as for /configure
    name: Option<String>,
}

/// Reply of GET /clone/<id>: the usual export reply plus where the clone
/// came from.
#[derive(Serialize)]
struct CloneReply {
    #[serde(flatten)]
    export: Message,
    bytes: u64,
    origin: String,
    layers: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    warning: Option<String>,
}

impl CloneReply {
    /// `bytes` is the reply's own field; the flattened export must not
    /// carry a second one (an existing volume's export does, and a
    /// strict JSON reader rejects the duplicate key).
    fn new(
        mut export: Message,
        bytes: u64,
        origin: String,
        layers: u32,
        warning: Option<String>,
    ) -> Self {
        export.bytes = None;
        Self {
            export,
            bytes,
            origin,
            layers,
            warning,
        }
    }
}

/// Reply of GET /utilization.
#[derive(Serialize, Debug, PartialEq)]
struct Utilization {
    vg: String,
    thin_pool: Option<String>,
    /// space volumes are carved from: the thin pool, or the whole VG
    bytes: u64,
    used_bytes: u64,
    free_bytes: u64,
    data_percent: f64,
    /// thin pool only; the pool stops working when its metadata fills up
    metadata_percent: Option<f64>,
    metadata_bytes: Option<u64>,
    /// thin pool: sum of the sizes promised to its volumes (may exceed
    /// `bytes`); otherwise the same as `used_bytes`
    provisioned_bytes: u64,
    vg_bytes: u64,
    /// unallocated VG space (what a thin pool could still be grown by)
    vg_free_bytes: u64,
    /// number of abe volumes
    volumes: usize,
    /// deepest snapshot chain in the VG
    max_layers: u32,
    /// one line per LV with more than MAX_SNAPSHOT_LAYERS snapshot layers
    warnings: Vec<String>,
    /// what the last startup (or GET /reexport) pass did
    #[serde(skip_serializing_if = "Option::is_none")]
    reexport: Option<ReexportSummary>,
}

/// What one re-export pass did (startup, GET /reexport, a retry).
#[derive(Serialize, Clone, Debug, Default, PartialEq)]
struct ReexportSummary {
    /// exported in this pass
    exported: usize,
    /// were already exported when the pass looked
    already: usize,
    /// could not be exported; the ids
    failed: Vec<String>,
    /// exported, but not on the port their abe_port tag named
    moved: usize,
    /// exported with no client recorded and none connected, so the port
    /// stays fenced shut until the next GET /id; the ids
    closed: Vec<String>,
    /// RFC 3339 time of the pass
    at: String,
    /// some failures were EADDRNOTAVAIL (the underlay address is not up
    /// yet), so a prompt retry is worth it
    #[serde(skip)]
    retry: bool,
}

/// The last pass, for /utilization.
static LAST_REEXPORT: Mutex<Option<ReexportSummary>> = Mutex::new(None);

fn last_reexport() -> Option<ReexportSummary> {
    LAST_REEXPORT
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

fn remember_reexport(s: &ReexportSummary) {
    *LAST_REEXPORT.lock().unwrap_or_else(|e| e.into_inner()) = Some(s.clone());
}

/// How long startup waits for every volume to be exported again before it
/// starts serving anyway (ABE_REEXPORT_WAIT seconds, default 90). Only
/// EADDRNOTAVAIL failures (the underlay address is not up yet) keep it
/// waiting; the pass is retried every 2 s.
fn reexport_wait() -> u64 {
    var("ABE_REEXPORT_WAIT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(90)
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Export every volume in the VG again, each on the port its `abe_port`
/// tag names when that is free, so exports survive a reboot or a fresh
/// nvmet module load (configfs is the only place they lived). Holds OPS
/// for the whole pass. One LV failing does not stop the others.
fn reexport_all() -> ReexportSummary {
    let _g = OPS.lock().unwrap_or_else(|e| e.into_inner());
    reexport_locked()
}

/// What `fence_rebuild` found exported.
#[derive(Default)]
struct FenceSync {
    /// exports that were up, with the client each port is open to
    already: Vec<(String, u16, Option<Ipv4Addr>)>,
    /// ids whose port stays closed: no client recorded, none connected
    closed: Vec<String>,
}

/// Under OPS: replace the fence with one that allows exactly the live
/// exports, each to its recorded client or, failing that, to the one
/// peer connected to it (an export made before the fence existed, which
/// is then tagged). One transaction, so a connection never meets an
/// empty table. Err only when nft fails; if lvs fails an empty fence
/// goes up (closed beats open) and the pass that follows reports it.
fn fence_rebuild() -> Result<FenceSync> {
    let mut sync = FenceSync::default();
    let lvs = match list_lvs() {
        Ok(l) => l,
        Err(e) => {
            warn!("fence: lvs failed ({e}); installing an empty fence");
            fence_install(&[], &[])?;
            return Ok(sync);
        }
    };
    let mut keep = Vec::new();
    let mut ports = Vec::new();
    for lv in lvs
        .iter()
        .filter(|l| is_volume_id(&l.name) && !has_tag(&l.tags, TAG_SEALED))
    {
        let id = &lv.name;
        let Some(port) = existing_export(id).and_then(|p| p.parse::<u16>().ok()) else {
            continue;
        };
        let tagged = tag_value(&lv.tags, TAG_CLIENT).and_then(|v| v.parse::<Ipv4Addr>().ok());
        let client = tagged.or_else(|| {
            let peers = established_peers(port);
            if peers.len() == 1 {
                let ip = *peers.iter().next().unwrap();
                info!("adopted {ip} for {id} on {port}");
                Some(ip)
            } else {
                info!(
                    "{id} on {port}: no client recorded and {} connected; closed until attached again",
                    peers.len()
                );
                None
            }
        });
        ports.push(port);
        match client {
            Some(ip) => keep.push((ip, port)),
            None => sync.closed.push(id.clone()),
        }
        sync.already.push((id.clone(), port, client));
    }
    fence_install(&ports, &keep)?;
    for (id, port, client) in &sync.already {
        if let Err(e) = lvs
            .iter()
            .find(|l| &l.name == id)
            .map_or(Ok(()), |lv| record_export(id, &lv.tags, *port, *client))
        {
            warn!("could not record port {port} on {id}: {e}");
        }
    }
    Ok(sync)
}

/// The fence is rebuilt first (`fence_rebuild`), then whatever is not
/// exported is exported and fenced to its recorded client.
fn reexport_locked() -> ReexportSummary {
    let mut s = ReexportSummary {
        at: now_rfc3339(),
        ..Default::default()
    };
    match fence_rebuild() {
        Ok(sync) => {
            s.already = sync.already.len();
            s.closed = sync.closed;
        }
        Err(e) => {
            error!("re-export: cannot install the nvmet fence: {e}; nothing re-exported");
            s.retry = true;
            return s;
        }
    }
    let mut lvs = match list_lvs() {
        Ok(l) => l,
        Err(e) => {
            error!("re-export: lvs failed: {e}");
            return s;
        }
    };
    lvs.retain(|l| is_volume_id(&l.name));
    lvs.sort_by(|a, b| a.name.cmp(&b.name));
    let (min, max) = port_bounds();
    let root = nvmet_path();
    let mut used = used_ports(Path::new(&root));
    for lv in &lvs {
        let id = &lv.name;
        if has_tag(&lv.tags, TAG_SEALED) {
            // sealed bases are never exported
            if existing_export(id).is_some() {
                match remove_export(id) {
                    Ok(_) => info!("re-export: unexported sealed base {id}"),
                    Err(e) => warn!("re-export: could not unexport sealed base {id}: {e}"),
                }
            }
            continue;
        }
        if existing_export(id).is_some() {
            continue; // counted above
        }
        match reexport_one(lv, &used, min, max) {
            Ok((port, moved, client)) => {
                used.insert(port);
                s.exported += 1;
                if moved {
                    s.moved += 1;
                }
                if client.is_none() {
                    s.closed.push(id.clone());
                }
            }
            Err(e) => {
                if e.raw_os_error() == Some(nix::libc::EADDRNOTAVAIL) {
                    s.retry = true;
                }
                error!("re-export of {id} failed: {e}");
                s.failed.push(id.clone());
            }
        }
    }
    info!(
        "re-export: exported={} already={} failed={} moved={} closed={}",
        s.exported,
        s.already,
        s.failed.len(),
        s.moved,
        s.closed.len()
    );
    s
}

/// The /utilization warning for a pass that left ports closed.
fn reexport_warning(s: &ReexportSummary) -> Option<String> {
    (!s.closed.is_empty()).then(|| {
        format!(
            "{} volume(s) exported with no client; closed until attached again",
            s.closed.len()
        )
    })
}

/// Activate (if needed) and export one volume, preferring its recorded
/// port, then open the port to its recorded client (or the one peer on
/// it; none for a fresh export, so a 0.4.0 volume without a connection
/// comes back closed). Ok((port, moved, client)).
fn reexport_one(
    lv: &Lv,
    used: &BTreeSet<u16>,
    min: u16,
    max: u16,
) -> Result<(u16, bool, Option<Ipv4Addr>)> {
    let id = &lv.name;
    if !lv.active {
        info!("re-export: activating {id}");
        // -K: ignore the activation-skip flag thin snapshots are born with
        let out = Command::new("/usr/sbin/lvchange")
            .args(["-y", "-ay", "-K", &format!("{}/{id}", vg_name())])
            .output()?;
        if let Err(e) = check(out, "lvchange -ay") {
            if let Some(pool) = thin_pool() {
                warn!(
                    "if {}/{pool} itself is inactive: install thin-provisioning-tools and check `journalctl -b | grep -i thin`",
                    vg_name()
                );
            }
            return Err(e);
        }
    }
    let old = tag_value(&lv.tags, TAG_PORT).and_then(|v| v.parse::<u16>().ok());
    let want = match old {
        Some(p) if (min..=max).contains(&p) && !used.contains(&p) => p,
        _ => {
            let p = lowest_free(used, min, max).ok_or_else(|| {
                Error::other(format!(
                    "no free nvmet port in {min}-{max} ({} exported)",
                    used.len()
                ))
            })?;
            match old {
                Some(o) => warn!("re-exporting {id} on {p} (was {o})"),
                None => info!("re-exporting {id} on {p} (no port recorded)"),
            }
            p
        }
    };
    export(id, want)?;
    let client = match refence(lv, want) {
        Ok(c) => c,
        Err(e) => {
            warn!("re-export of {id}: cannot fence {want}: {e}; unexporting");
            if let Err(e2) = remove_export(id) {
                warn!("cleanup of {id} failed too: {e2}");
            }
            return Err(e);
        }
    };
    if client.is_none() {
        set_port_tag(id, &lv.tags, want)?;
    }
    Ok((want, old.is_some_and(|o| o != want), client))
}

/// GET /reexport: run the startup pass again and report what it did.
async fn reexport() -> std::result::Result<Json<ReexportSummary>, ApiError> {
    run_blocking(move || {
        let s = reexport_all();
        remember_reexport(&s);
        Ok(s)
    })
    .await
    .map(Json)
}

/// Startup: re-export everything before the listener is bound, retrying
/// while the underlay address is still missing, then keep retrying any
/// leftovers in the background.
async fn reexport_at_startup() {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(reexport_wait());
    let summary = loop {
        let s = match tokio::task::spawn_blocking(reexport_all).await {
            Ok(s) => s,
            Err(e) => {
                error!("re-export task: {e}");
                break ReexportSummary::default();
            }
        };
        remember_reexport(&s);
        if !s.retry || std::time::Instant::now() >= deadline {
            break s;
        }
        info!("re-export: address not available yet; retrying in 2s");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    };
    if summary.failed.is_empty() {
        return;
    }
    warn!(
        "re-export: {} volume(s) still not exported; retrying every 10s",
        summary.failed.len()
    );
    tokio::spawn(async {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            match tokio::task::spawn_blocking(reexport_all).await {
                Ok(s) => {
                    remember_reexport(&s);
                    if s.failed.is_empty() {
                        info!("re-export: every volume is exported now");
                        break;
                    }
                }
                Err(e) => error!("re-export retry task: {e}"),
            }
        }
    });
}

/// One row of `lvs`.
#[derive(Debug, Clone, PartialEq)]
struct Lv {
    name: String,
    bytes: u64,
    pool: Option<String>,
    origin: Option<String>,
    data_percent: Option<f64>,
    metadata_percent: Option<f64>,
    metadata_bytes: Option<u64>,
    segtype: String,
    /// LVM tags; abe's own are listed under TAG_*
    tags: Vec<String>,
    active: bool,
}

// LV tags: durable per-volume metadata that lives in the VG metadata and
// survives reboots without a state file.
/// `abe_port=<n>`: trsvcid the volume is exported on; re-export reuses it.
const TAG_PORT: &str = "abe_port";
/// `abe_name=<name>`: the caller's name, for idempotent create.
const TAG_NAME: &str = "abe_name";
/// `abe_base=<image>`: this volume is the base for `<image>`.
const TAG_BASE: &str = "abe_base";
/// `abe_sealed`: a base that is filled and frozen: never exported, clone-only.
const TAG_SEALED: &str = "abe_sealed";
/// `abe_client=<ipv4>`: the address the port is fenced to (the caller of
/// the last /configure, /id or /clone); re-export opens it to the same.
const TAG_CLIENT: &str = "abe_client";

/// Value of the `key=value` tag, if present.
fn tag_value<'a>(tags: &'a [String], key: &str) -> Option<&'a str> {
    tags.iter().find_map(|t| {
        let (k, v) = t.split_once('=')?;
        (k == key).then_some(v)
    })
}

/// Is the bare tag `key` (or any `key=...`) present?
fn has_tag(tags: &[String], key: &str) -> bool {
    tags.iter()
        .any(|t| t == key || t.split_once('=').is_some_and(|(k, _)| k == key))
}

/// Caller-supplied tag values (`name`, `image`) must match
/// `^[A-Za-z0-9._+:-]{1,128}$`: a safe subset of what LVM allows in a tag.
fn valid_tag_value(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | ':' | '-'))
}

/// `lvchange --deltag .. --addtag .. vg/id` in one call. No-op when both
/// lists are empty.
fn retag(id: &str, del: &[String], add: &[String]) -> Result<()> {
    if del.is_empty() && add.is_empty() {
        return Ok(());
    }
    let mut cmd = Command::new("/usr/sbin/lvchange");
    for t in del {
        cmd.args(["--deltag", t]);
    }
    for t in add {
        cmd.args(["--addtag", t]);
    }
    cmd.arg(format!("{}/{id}", vg_name()));
    check(cmd.output()?, "lvchange tags")
}

/// Record the port `id` is exported on, replacing any earlier record.
fn set_port_tag(id: &str, tags: &[String], port: u16) -> Result<()> {
    record_export(id, tags, port, None)
}

/// Record the port `id` is exported on and (when known) the client its
/// port is open to, replacing earlier records of either, in one lvchange.
/// `client: None` leaves any `abe_client` tag alone.
fn record_export(id: &str, tags: &[String], port: u16, client: Option<Ipv4Addr>) -> Result<()> {
    let mut add = vec![format!("{TAG_PORT}={port}")];
    if let Some(ip) = client {
        add.push(format!("{TAG_CLIENT}={ip}"));
    }
    let mut del = Vec::new();
    for t in tags {
        let stale =
            t.starts_with("abe_port=") || (client.is_some() && t.starts_with("abe_client="));
        if stale && !add.contains(t) {
            del.push(t.clone());
        }
    }
    add.retain(|t| !tags.contains(t));
    retag(id, &del, &add)
}

/// Under OPS: open `port` to the volume's recorded client, or adopt the
/// one peer connected to it (an export made before the fence existed) and
/// record that. Ok(None): nobody to open it to; the port stays closed.
fn refence(lv: &Lv, port: u16) -> Result<Option<Ipv4Addr>> {
    let id = &lv.name;
    let tagged = tag_value(&lv.tags, TAG_CLIENT).and_then(|v| v.parse::<Ipv4Addr>().ok());
    let client = match tagged {
        Some(ip) => ip,
        None => {
            let peers = established_peers(port);
            if peers.len() != 1 {
                info!(
                    "{id} on {port}: no client recorded and {} connected; closed until attached again",
                    peers.len()
                );
                fence_close_port(port)?;
                return Ok(None);
            }
            let ip = *peers.iter().next().unwrap();
            info!("adopted {ip} for {id} on {port}");
            ip
        }
    };
    fence_open(client, port)?;
    if let Err(e) = record_export(id, &lv.tags, port, Some(client)) {
        warn!("could not record {client} on {id}: {e}");
    }
    Ok(Some(client))
}

/// The abe volume carrying exactly this tag, if any.
fn find_tagged<'a>(lvs: &'a [Lv], tag: &str) -> Option<&'a Lv> {
    lvs.iter()
        .find(|l| is_volume_id(&l.name) && l.tags.iter().any(|t| t == tag))
}

/// What a create request is asking for, in bytes, when that is knowable
/// (`?bytes=` always; `?size=` for the usual lvcreate suffixes).
fn parse_lv_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    let n: u64 = digits.parse().ok()?;
    let unit = s[digits.len()..]
        .trim()
        .to_ascii_lowercase()
        .trim_end_matches("ib")
        .trim_end_matches('b')
        .to_string();
    let shift = match unit.as_str() {
        "" | "m" => 20,
        "k" => 10,
        "g" => 30,
        "t" => 40,
        "p" => 50,
        _ => return None,
    };
    n.checked_shl(shift)
}

async fn configure(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(p): Query<ConfigureParams>,
) -> std::result::Result<Json<Message>, ApiError> {
    let client = client_ip(peer).map_err(Fail::into_api)?;
    let size = match (p.bytes, p.size) {
        (Some(b), _) => bytes_to_lv_size(b),
        (None, Some(s)) if !s.is_empty() => s,
        _ => default_vol_size(),
    };
    for (what, v) in [("name", &p.name), ("base", &p.base)] {
        if let Some(v) = v {
            if !valid_tag_value(v) {
                return Err(Fail::bad_request(format!(
                    "bad {what} {v:?}: use [A-Za-z0-9._+:-]{{1,128}}"
                ))
                .into_api());
            }
        }
    }
    // A base is filled with a disk image, which brings its own partition
    // table, and is never measured.
    let raw = p.raw.unwrap_or(false) || p.base.is_some();
    let want = p.bytes.or_else(|| parse_lv_size(&size));
    let (name, base) = (p.name.clone(), p.base.clone());
    let mut m = run_blocking(move || {
        with_ops(|| {
            let mut tags = Vec::new();
            if name.is_some() || base.is_some() {
                let lvs = list_lvs().map_err(Fail::ctx("lvs"))?;
                if let Some(image) = &base {
                    if let Some(lv) = find_tagged(&lvs, &format!("{TAG_BASE}={image}")) {
                        return existing_base(lv, image, want, client);
                    }
                    tags.push(format!("{TAG_BASE}={image}"));
                }
                if let Some(name) = &name {
                    if let Some(lv) = find_tagged(&lvs, &format!("{TAG_NAME}={name}")) {
                        return existing_named(lv, name, want, client);
                    }
                    tags.push(format!("{TAG_NAME}={name}"));
                }
            }
            let id = new_id();
            info!("configure: new volume {id} ({size}, raw={raw}, name={name:?}, base={base:?}) for {client}");
            let (mut m, _port) = create_and_export(&id, &size, raw, &tags, client)?;
            if base.is_some() {
                m.base = base.clone();
                m.sealed = Some(false);
            }
            Ok(m)
        })
    })
    .await?;
    if m.existing || m.base.is_some() {
        return Ok(Json(m));
    }
    let id = m.id.clone();
    // Measure after the export is set up so a fio problem cannot cost the
    // caller its volume. fio stays inside partition 1 on a non-raw volume
    // and the region is trimmed afterwards, so the caller gets a blank
    // volume that occupies nothing in the pool.
    let dev = lv_path_for_uuid(&id);
    let thin = thin_pool().is_some();
    m.perf = match fio_region(m.bytes.unwrap_or(0), raw) {
        None => {
            info!("{id}: too small for the fio check; skipped");
            None
        }
        Some(region) => {
            let dev = dev.clone();
            match tokio::task::spawn_blocking(move || characterize(&dev, region, thin)).await {
                Ok(Ok(p)) => p,
                Ok(Err(e)) => {
                    warn!("fio on {id}: {e}");
                    None
                }
                Err(e) => {
                    warn!("fio task on {id}: {e}");
                    None
                }
            }
        }
    };
    if !raw && m.perf.is_some() {
        // Should never fire; turns a silent corruption into a loud one.
        let (d, i) = (dev.clone(), id.clone());
        match tokio::task::spawn_blocking(move || gpt_intact(&d, &i)).await {
            Ok(Ok(true)) => {}
            Ok(Ok(false)) => {
                error!("fio damaged the partition table of {id}; removing it");
                let i = id.clone();
                if let Err(e) = run_blocking(move || with_ops(|| remove_volume(&i))).await {
                    warn!("could not remove {id}: {}", e.1.error);
                }
                return Err(Fail::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("fio damaged the partition table of {id}"),
                )
                .into_api());
            }
            Ok(Err(e)) => warn!("could not verify the partition table of {id}: {e}"),
            Err(e) => warn!("parted task on {id}: {e}"),
        }
    }
    Ok(Json(m))
}

const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;

/// Where fio writes on a new volume.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Region {
    offset: u64,
    len: u64,
}

/// The fio region for a volume of `bytes`: the first GiB of a raw volume;
/// inside partition 1 (which `parted mkpart primary 1MiB 100%` starts at
/// 1 MiB) and 1 MiB clear of the backup GPT in the last 33 sectors
/// otherwise. Whole MiBs, so a trim frees every thin chunk it covers.
/// None when there is not 16 MiB to write on.
fn fio_region(bytes: u64, raw: bool) -> Option<Region> {
    let (start, end) = if raw {
        (0, bytes)
    } else {
        (MIB, bytes.saturating_sub(MIB))
    };
    let len = (end.saturating_sub(start)).min(GIB) & !(MIB - 1);
    (len >= 16 * MIB).then_some(Region { offset: start, len })
}

/// Under OPS: `?name=` matched `lv`. Hand it back (exported) unless it is
/// smaller than what is being asked for now.
fn existing_named(lv: &Lv, name: &str, want: Option<u64>, client: Ipv4Addr) -> Res<Message> {
    if let Some(w) = want {
        if lv.bytes < w {
            return Err(Fail::conflict(format!(
                "{} is already named {name} but has {} bytes, fewer than the {w} requested",
                lv.name, lv.bytes
            )));
        }
    }
    info!("{name}: returning existing volume {}", lv.name);
    let mut m = export_or_existing(&lv.name, &lv.tags, client)?;
    m.existing = true;
    Ok(m)
}

/// Under OPS: `?base=` matched `lv`. A sealed base comes back unexported;
/// an unsealed one exported, for filling.
fn existing_base(lv: &Lv, image: &str, want: Option<u64>, client: Ipv4Addr) -> Res<Message> {
    if let Some(w) = want {
        if lv.bytes < w {
            return Err(Fail::conflict(format!(
                "base {} for {image} has {} bytes, fewer than the {w} requested",
                lv.name, lv.bytes
            )));
        }
    }
    if has_tag(&lv.tags, TAG_SEALED) {
        info!("{image}: returning sealed base {}", lv.name);
        return Ok(Message::sealed_base(lv, image));
    }
    info!("{image}: returning unsealed base {}", lv.name);
    let mut m = export_or_existing(&lv.name, &lv.tags, client)?;
    m.existing = true;
    m.base = Some(image.to_string());
    m.sealed = Some(false);
    Ok(m)
}

/// GET /seal/<id>: a filled base is frozen: unexported, never exported
/// again, clone-only. Idempotent.
async fn seal(EP(id): EP<String>) -> std::result::Result<Json<SealReply>, ApiError> {
    info!("seal {id}");
    run_blocking(move || {
        with_ops(|| {
            let lvs = list_lvs().map_err(Fail::ctx("lvs"))?;
            let lv = lvs
                .iter()
                .find(|l| l.name == id)
                .ok_or_else(|| Fail::not_found(&id))?;
            let Some(image) = tag_value(&lv.tags, TAG_BASE) else {
                return Err(Fail::bad_request(format!("{id} is not a base volume")));
            };
            remove_export(&id).map_err(Fail::ctx("nvmet teardown"))?;
            let del: Vec<String> = lv
                .tags
                .iter()
                .filter(|t| t.starts_with("abe_port=") || t.starts_with("abe_client="))
                .cloned()
                .collect();
            let add: Vec<String> = (!has_tag(&lv.tags, TAG_SEALED))
                .then(|| TAG_SEALED.to_string())
                .into_iter()
                .collect();
            retag(&id, &del, &add).map_err(Fail::ctx("lvchange tags"))?;
            info!("sealed base {id} for {image}");
            Ok(SealReply {
                id: id.clone(),
                base: image.to_string(),
                sealed: true,
                bytes: lv.bytes,
            })
        })
    })
    .await
    .map(Json)
}

/// GET /version: what this abe is and can do.
async fn version() -> Json<Version> {
    Json(version_info())
}

fn version_info() -> Version {
    let mut features = vec!["reexport", "ports", "name", "trim", "tls", "fence"];
    if thin_pool().is_some() {
        // bases are only useful as thin clone origins
        features.extend(["base", "clone"]);
    }
    Version {
        version: env!("CARGO_PKG_VERSION"),
        features,
        tls: tls_enabled(),
    }
}

/// Under OPS: make the LV, export it on a free port open to `client` and
/// tag it with `abe_port=<port>`, `abe_client=<client>` plus `tags`. If
/// anything after lvcreate fails the LV is removed again, so a failed
/// create leaves nothing behind.
fn create_and_export(
    id: &str,
    size: &str,
    raw: bool,
    tags: &[String],
    client: Ipv4Addr,
) -> Res<(Message, u16)> {
    create_lv(id, size, raw).map_err(Fail::ctx("create_lv"))?;
    export_new(id, tags, client).inspect_err(|_| rollback_lv(id))
}

/// Under OPS: export `id` on `port` and open the port to `client`. If
/// the fence cannot be opened the export is torn down again: a volume
/// nobody can reach is worse than an error.
fn export_to(id: &str, port: u16, client: Ipv4Addr) -> Result<Message> {
    info!("exporting {id} on {port} for {client}");
    let mut m = export(id, port)?;
    if let Err(e) = fence_open(client, port) {
        warn!("cannot open {port} to {client}: {e}; unexporting {id}");
        if let Err(e2) = remove_export(id) {
            warn!("cleanup of {id} failed too: {e2}");
        }
        return Err(Error::other(format!("fence: {e}")));
    }
    m.client = Some(client.to_string());
    Ok(m)
}

/// Under OPS, for an LV that was just created: pick a port, export, open
/// it to `client`, tag. configfs is cleaned up on failure; the LV is the
/// caller's to roll back.
fn export_new(id: &str, tags: &[String], client: Ipv4Addr) -> Res<(Message, u16)> {
    let port = pick_port()?;
    let m = export_to(id, port, client).map_err(Fail::ctx("export"))?;
    let mut add = tags.to_vec();
    add.push(format!("{TAG_PORT}={port}"));
    add.push(format!("{TAG_CLIENT}={client}"));
    if let Err(e) = retag(id, &[], &add) {
        if let Err(e2) = remove_export(id) {
            warn!("could not unexport {id} after a tagging failure: {e2}");
        }
        return Err(Fail::ctx("lvchange tags")(e));
    }
    Ok((m, port))
}

/// Best effort `lvremove` of a volume whose creation failed half-way.
fn rollback_lv(id: &str) {
    let lv = lv_path_for_uuid(id);
    if !Path::new(&lv).exists() {
        return;
    }
    if let Err(e) = remove_holders(&lv) {
        warn!("rollback of {id}: {e}");
    }
    match Command::new("/usr/sbin/lvremove")
        .args(["-y", &lv])
        .output()
    {
        Ok(o) if o.status.success() => info!("rolled back {lv}"),
        Ok(o) => warn!(
            "could not roll back {lv}: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => warn!("could not roll back {lv}: {e}"),
    }
}

/// Under OPS: export `id` if it is not already, open its port to
/// `client` (moving it away from whoever had it), record both, and
/// return the connect reply (GET /id and named/base retries).
fn export_or_existing(id: &str, tags: &[String], client: Ipv4Addr) -> Res<Message> {
    if has_tag(tags, TAG_SEALED) {
        return Err(Fail::conflict(format!("{id} is a sealed base; clone it")));
    }
    let (m, port) = match existing_export(id) {
        Some(svc) => {
            info!("{id} already exported on port {svc}; fencing it to {client}");
            let port = svc.parse::<u16>().map_err(|e| {
                Fail::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("{id}: trsvcid {svc:?}: {e}"),
                )
            })?;
            fence_open(client, port).map_err(Fail::ctx("fence"))?;
            let mut m = Message::exported(id, &svc);
            m.client = Some(client.to_string());
            (m, port)
        }
        None => {
            let port = pick_port()?;
            (
                export_to(id, port, client).map_err(Fail::ctx("export"))?,
                port,
            )
        }
    };
    // The export is up; the tags only matter for the next restart.
    if let Err(e) = record_export(id, tags, port, Some(client)) {
        warn!("could not record port {port} and client {client} on {id}: {e}");
    }
    Ok(m)
}

/// Direct-I/O fio straight at the LV: random writes at ABE_FIO_BS,
/// ABE_FIO_IODEPTH in flight, over `region` (never the dm partition
/// device, which would hold the LV open), ABE_FIO_RAMP seconds of
/// warm-up that fio does not count (device queues, caches and the first
/// thin-chunk allocations settle), then ABE_FIO_SECONDS measured. The
/// region is trimmed afterwards. Ok(None) when disabled. Runs outside
/// OPS.
fn characterize(dev: &str, region: Region, thin: bool) -> Result<Option<Perf>> {
    let secs = fio_seconds();
    if secs == 0 {
        return Ok(None);
    }
    let (bs, iodepth, ramp) = (fio_bs(), fio_iodepth(), fio_ramp());
    info!(
        "fio: {ramp}s warm-up then {secs}s of {bs} random writes, iodepth {iodepth}, on {} bytes at offset {} of {dev}",
        region.len, region.offset
    );
    let out = Command::new("fio")
        .args([
            "--name=abe",
            "--filename",
            dev,
            "--rw=randwrite",
            "--bs",
            &bs,
            "--iodepth",
            &iodepth.to_string(),
            "--offset",
            &region.offset.to_string(),
            "--size",
            &region.len.to_string(),
            "--direct=1",
            "--ioengine=libaio",
            "--time_based",
            "--ramp_time",
            &ramp.to_string(),
            "--runtime",
            &secs.to_string(),
            "--output-format=json",
        ])
        .output()?;
    check(out.clone(), "fio")?;
    let mut perf = parse_fio(&String::from_utf8_lossy(&out.stdout), &bs, iodepth)
        .ok_or_else(|| Error::other("fio printed no write results"))?;
    info!(
        "fio on {dev}: {:.0} us mean latency, {:.0} IOPS, {:.1} MiB/s at bs={bs} iodepth={iodepth}",
        perf.write_lat_us, perf.write_iops, perf.write_mib_s
    );
    perf.trimmed = match trim(dev, region, thin) {
        Ok(()) => true,
        Err(e) => {
            warn!("trim of the fio region on {dev} failed: {e}");
            false
        }
    };
    Ok(Some(perf))
}

/// Give the fio region back: `blkdiscard` on a thin volume returns every
/// fully covered chunk to the pool (and reads come back as zeros);
/// `blkdiscard --zeroout` on a thick one frees nothing but leaves the
/// region blank. `--force` because util-linux >= 2.38 refuses a device
/// carrying a signature (the GPT on a non-raw volume) without it; the
/// offset and length keep the trim inside partition 1 regardless.
fn trim(dev: &str, region: Region, thin: bool) -> Result<()> {
    let mut cmd = Command::new("blkdiscard");
    cmd.arg("--force");
    if !thin {
        cmd.arg("--zeroout");
    }
    cmd.args([
        "--offset",
        &region.offset.to_string(),
        "--length",
        &region.len.to_string(),
        dev,
    ]);
    check(cmd.output()?, "blkdiscard")?;
    info!(
        "{}: {} bytes at offset {} of {dev}",
        if thin { "discarded" } else { "zeroed" },
        region.len,
        region.offset
    );
    Ok(())
}

/// Does `dev` still carry partition 1, starting at 1 MiB and named `id`?
fn gpt_intact(dev: &str, id: &str) -> Result<bool> {
    let out = Command::new("/usr/sbin/parted")
        .args(["-s", "-m", dev, "unit", "B", "print"])
        .output()?;
    check(out.clone(), "parted print")?;
    Ok(parse_parted_part1(&String::from_utf8_lossy(&out.stdout))
        .is_some_and(|(start, name)| start == MIB && name == id))
}

/// (start in bytes, name) of partition 1 in `parted -s -m <dev> unit B print`.
fn parse_parted_part1(text: &str) -> Option<(u64, String)> {
    text.lines().find_map(|l| {
        let f: Vec<&str> = l.trim().trim_end_matches(';').split(':').collect();
        if f.first() != Some(&"1") || f.len() < 6 {
            return None;
        }
        let start = f[1].trim_end_matches('B').parse().ok()?;
        Some((start, f[5].to_string()))
    })
}

/// Startup check: a thin pool with `discards=ignore` cannot give the fio
/// region back, so the trim after each create is wasted.
fn warn_if_discards_ignored() {
    let Some(pool) = thin_pool() else { return };
    let vg = vg_name();
    let out = Command::new("/usr/sbin/lvs")
        .env("LC_ALL", "C")
        .args(["--noheadings", "-o", "discards", &format!("{vg}/{pool}")])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            if String::from_utf8_lossy(&o.stdout).trim() == "ignore" {
                warn!("thin pool discards=ignore: the fio region cannot be returned to the pool; run lvchange --discards passdown {vg}/{pool}");
            }
        }
        Ok(o) => warn!(
            "cannot read the discard mode of {vg}/{pool}: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => warn!("cannot read the discard mode of {vg}/{pool}: {e}"),
    }
}

/// Pull the write numbers out of `fio --output-format=json`.
fn parse_fio(json: &str, bs: &str, iodepth: u32) -> Option<Perf> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let w = v.get("jobs")?.as_array()?.first()?.get("write")?;
    let runtime_ms = w.get("runtime")?.as_f64()?;
    let bw_bytes = w.get("bw_bytes")?.as_f64()?;
    let iops = w.get("iops")?.as_f64()?;
    let lat_ns = w
        .get("clat_ns")
        .and_then(|c| c.get("mean"))
        .and_then(|m| m.as_f64())
        .unwrap_or(0.0);
    let round = |x: f64| (x * 100.0).round() / 100.0;
    Some(Perf {
        bs: bs.to_string(),
        iodepth,
        seconds: round(runtime_ms / 1000.0),
        write_mib_s: round(bw_bytes / (1024.0 * 1024.0)),
        write_iops: round(iops),
        write_lat_us: round(lat_ns / 1e3),
        trimmed: false,
    })
}

/// GET /id/<id>: (re-)export an existing volume. Idempotent.
async fn attach(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    EP(id): EP<String>,
) -> std::result::Result<Json<Message>, ApiError> {
    let client = client_ip(peer).map_err(Fail::into_api)?;
    info!("attach id is {id} for {client}");
    run_blocking(move || {
        with_ops(|| {
            let lvs = list_lvs().map_err(Fail::ctx("lvs"))?;
            let lv = lvs
                .iter()
                .find(|l| l.name == id)
                .ok_or_else(|| Fail::not_found(&id))?;
            export_or_existing(&id, &lv.tags, client)
        })
    })
    .await
    .map(Json)
}

/// DELETE /id/<id>: stop exporting the volume and remove its LV.
/// Idempotent: returns 404 only if neither an export nor an LV exists.
async fn detach(EP(id): EP<String>) -> std::result::Result<Json<Message>, ApiError> {
    info!("delete id is {}", id);
    run_blocking(move || with_ops(|| remove_volume(&id)))
        .await
        .map(Json)
}

/// Under OPS: unexport and lvremove.
fn remove_volume(id: &str) -> Res<Message> {
    let lv = lv_path_for_uuid(id);
    let exported = existing_export(id).is_some();
    if !exported && !Path::new(&lv).exists() {
        return Err(Fail::not_found(id));
    }
    if let Ok(lvs) = list_lvs() {
        if let Some(image) = lvs
            .iter()
            .find(|l| l.name == id)
            .and_then(|l| tag_value(&l.tags, TAG_BASE))
        {
            // thin snapshots do not depend on their origin LV
            let clones = lvs
                .iter()
                .filter(|l| l.origin.as_deref() == Some(id))
                .count();
            warn!("deleting base {image} ({id}); {clones} clones keep their data");
        }
    }
    let port = remove_export(id).map_err(Fail::ctx("nvmet teardown"))?;
    if Path::new(&lv).exists() {
        remove_holders(&lv).map_err(Fail::ctx("remove partition mappings"))?;
        check(
            Command::new("/usr/sbin/lvremove")
                .args(["-y", &lv])
                .output()
                .map_err(Fail::ctx("lvremove"))?,
            "lvremove",
        )
        .map_err(Fail::ctx("lvremove"))?;
    }
    Ok(Message {
        message: format!("deleted {id}"),
        nqn: id.to_string(),
        id: id.to_string(),
        port: port.unwrap_or_default(),
        traddr: advertised_traddr(),
        bytes: None,
        perf: None,
        existing: false,
        base: None,
        sealed: None,
        client: None,
    })
}

/// GET /volumes: every volume in the VG (exported or not).
async fn volumes() -> std::result::Result<Json<Vec<Volume>>, ApiError> {
    list_volumes().map(Json).map_err(|e| api_err("lvs", e))
}

/// GET /utilization: how full the thin pool (or VG) is.
async fn utilization() -> std::result::Result<Json<Utilization>, ApiError> {
    let lvs = list_lvs().map_err(|e| api_err("lvs", e))?;
    let (vg_bytes, vg_free) = vg_space().map_err(|e| api_err("vgs", e))?;
    let mut u = summarize(&vg_name(), thin_pool().as_deref(), &lvs, vg_bytes, vg_free)
        .map_err(|e| api_err("utilization", e))?;
    u.reexport = last_reexport();
    if let Some(w) = u.reexport.as_ref().and_then(reexport_warning) {
        u.warnings.push(w);
    }
    Ok(Json(u))
}

/// GET /clone/<id>[?bytes=N]: create a new volume that starts out as a copy
/// of <id> (a thin snapshot: it shares the origin's blocks until either side
/// writes) and export it. The origin may be any thin volume in abe's pool.
async fn clone_volume(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    EP(origin): EP<String>,
    Query(p): Query<CloneParams>,
) -> std::result::Result<Json<CloneReply>, ApiError> {
    let client = client_ip(peer).map_err(Fail::into_api)?;
    info!("clone of {origin} for {client}");
    run_blocking(move || with_ops(|| clone_locked(&origin, &p, client)))
        .await
        .map(Json)
}

/// Under OPS: the whole of /clone (no fio runs on a clone).
fn clone_locked(origin: &str, p: &CloneParams, client: Ipv4Addr) -> Res<CloneReply> {
    if let Some(n) = &p.name {
        if !valid_tag_value(n) {
            return Err(Fail::bad_request(format!(
                "bad name {n:?}: use [A-Za-z0-9._+:-]{{1,128}}"
            )));
        }
    }
    let lvs = list_lvs().map_err(Fail::ctx("lvs"))?;
    if let Some(name) = &p.name {
        // A retry: the clone exists (even if its origin is gone by now).
        if let Some(lv) = find_tagged(&lvs, &format!("{TAG_NAME}={name}")) {
            let export = existing_named(lv, name, p.bytes, client)?;
            let n = layers(&lvs, &lv.name);
            return Ok(CloneReply::new(
                export,
                lv.bytes,
                lv.origin.clone().unwrap_or_else(|| origin.to_string()),
                n,
                layer_warning(&lv.name, n),
            ));
        }
    }
    let Some(src) = lvs.iter().find(|l| l.name == origin) else {
        return Err(Fail::not_found(origin));
    };
    if src.segtype != "thin" || src.pool.is_none() || src.pool != thin_pool() {
        return Err(Fail::bad_request(format!(
            "{origin} is not a thin volume in abe's pool ({}/{}); only those can be cloned",
            vg_name(),
            thin_pool().unwrap_or_else(|| "<ABE_THIN_POOL not set>".to_string())
        )));
    }
    if let Some(b) = p.bytes {
        if b < src.bytes {
            return Err(Fail::bad_request(format!(
                "a clone cannot be smaller than its origin ({b} < {} bytes)",
                src.bytes
            )));
        }
    }
    if has_tag(&src.tags, TAG_BASE) && !has_tag(&src.tags, TAG_SEALED) {
        return Err(Fail::conflict(format!("base {origin} is not sealed yet")));
    }
    let grow_to = p.bytes.filter(|b| *b > src.bytes);

    let id = new_id();
    let layers = layers(&lvs, origin) + 1;
    let warning = layer_warning(&id, layers);
    if let Some(w) = &warning {
        warn!("{w}");
    }
    clone_lv(origin, &id, grow_to).map_err(Fail::ctx("clone_lv"))?;
    let tags: Vec<String> = p.name.iter().map(|n| format!("{TAG_NAME}={n}")).collect();
    let (export, _port) = strip_inherited_tags(&id)
        .map_err(Fail::ctx("lvchange tags"))
        .and_then(|_| export_new(&id, &tags, client))
        .inspect_err(|_| rollback_lv(&id))?;
    let bytes = export.bytes.unwrap_or(grow_to.unwrap_or(src.bytes));
    Ok(CloneReply::new(
        export,
        bytes,
        origin.to_string(),
        layers,
        warning,
    ))
}

/// A snapshot may have inherited its origin's abe_* tags (base, sealed,
/// name, port); none of them are true of the clone.
fn strip_inherited_tags(id: &str) -> Result<()> {
    let lvs = list_lvs()?;
    let Some(lv) = lvs.iter().find(|l| l.name == id) else {
        return Ok(());
    };
    let del: Vec<String> = lv
        .tags
        .iter()
        .filter(|t| t.starts_with("abe_"))
        .cloned()
        .collect();
    if !del.is_empty() {
        info!("{id}: dropping inherited tags {del:?}");
    }
    retag(id, &del, &[])
}

/// Thin snapshot of `origin` named `name`, activated, optionally grown to
/// `grow_to` bytes. Nothing is left behind if a step fails.
fn clone_lv(origin: &str, name: &str, grow_to: Option<u64>) -> Result<()> {
    let vg = vg_name();
    let lv = format!("{vg}/{name}");
    info!("making thin snapshot {lv} of {vg}/{origin}");
    check(
        Command::new("/usr/sbin/lvcreate")
            .args(["-y", "-s", "-n", name, &format!("{vg}/{origin}")])
            .output()?,
        "lvcreate -s",
    )?;
    // Thin snapshots are created with the activation-skip flag set; clear it
    // so the volume comes up now and after every reboot.
    let finish = || -> Result<()> {
        check(
            Command::new("/usr/sbin/lvchange")
                .args(["-y", "-kn", &lv])
                .output()?,
            "lvchange -kn",
        )?;
        check(
            Command::new("/usr/sbin/lvchange")
                .args(["-y", "-ay", &lv])
                .output()?,
            "lvchange -ay",
        )?;
        if let Some(b) = grow_to {
            check(
                Command::new("/usr/sbin/lvextend")
                    .args(["-y", "-L", &bytes_to_lv_size(b), &lv])
                    .output()?,
                "lvextend",
            )?;
        }
        Ok(())
    };
    if let Err(e) = finish() {
        match Command::new("/usr/sbin/lvremove")
            .args(["-y", &lv])
            .output()
        {
            Ok(o) if o.status.success() => info!("removed half-made clone {lv}"),
            _ => warn!("could not remove half-made clone {lv}"),
        }
        return Err(e);
    }
    info!("created {} as a clone of {origin}", lv_path_for_uuid(name));
    Ok(())
}

/// abe's own volumes are named by their id: 32 hex chars.
fn is_volume_id(name: &str) -> bool {
    name.len() == 32 && name.chars().all(|c| c.is_ascii_hexdigit())
}

/// `lv_tags` and `lv_active` are last so the earlier indices never move.
const LVS_FIELDS: &str =
    "lv_name,lv_size,pool_lv,origin,data_percent,metadata_percent,lv_metadata_size,segtype,lv_tags,lv_active";

/// Every LV in the VG.
fn list_lvs() -> Result<Vec<Lv>> {
    let out = Command::new("/usr/sbin/lvs")
        .env("LC_ALL", "C")
        .args([
            "--noheadings",
            "--units",
            "b",
            "--nosuffix",
            "--separator",
            "|",
            "-o",
            LVS_FIELDS,
            &vg_name(),
        ])
        .output()?;
    check(out.clone(), "lvs")?;
    Ok(parse_lvs(&String::from_utf8_lossy(&out.stdout)))
}

/// Parse `lvs --noheadings --units b --nosuffix --separator '|' -o LVS_FIELDS`.
/// Tags come comma-separated; `lv_active` is `active` or empty.
fn parse_lvs(text: &str) -> Vec<Lv> {
    let some = |s: &str| (!s.is_empty()).then(|| s.to_string());
    let mut lvs = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split('|').map(str::trim).collect();
        if f.len() < 8 || f[0].is_empty() {
            continue;
        }
        let Ok(bytes) = f[1].parse() else { continue };
        lvs.push(Lv {
            name: f[0].to_string(),
            bytes,
            pool: some(f[2]),
            // lvs brackets the names of hidden LVs
            origin: some(f[3].trim_start_matches('[').trim_end_matches(']')),
            data_percent: f[4].parse().ok(),
            metadata_percent: f[5].parse().ok(),
            metadata_bytes: f[6].parse().ok(),
            segtype: f[7].to_string(),
            tags: f
                .get(8)
                .map(|t| {
                    t.split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
            active: f.get(9).is_none_or(|a| a.starts_with("active")),
        });
    }
    lvs
}

/// (size, free) of the VG in bytes.
fn vg_space() -> Result<(u64, u64)> {
    let out = Command::new("/usr/sbin/vgs")
        .env("LC_ALL", "C")
        .args([
            "--noheadings",
            "--units",
            "b",
            "--nosuffix",
            "--separator",
            "|",
            "-o",
            "vg_size,vg_free",
            &vg_name(),
        ])
        .output()?;
    check(out.clone(), "vgs")?;
    let text = String::from_utf8_lossy(&out.stdout);
    parse_vgs(&text)
        .ok_or_else(|| Error::other(format!("cannot parse vgs output {:?}", text.trim())))
}

fn parse_vgs(text: &str) -> Option<(u64, u64)> {
    let mut f = text
        .lines()
        .find(|l| !l.trim().is_empty())?
        .split('|')
        .map(str::trim);
    Some((f.next()?.parse().ok()?, f.next()?.parse().ok()?))
}

/// Snapshot layers under `name`: how many origins lvs reports beneath it.
/// LVM drops the link when an origin is removed, so this counts the layers
/// that still exist as volumes.
fn layers(lvs: &[Lv], name: &str) -> u32 {
    let mut depth = 0;
    let mut cur = name;
    // the bound only matters if the report were ever to contain a loop
    while (depth as usize) < lvs.len() {
        match lvs
            .iter()
            .find(|l| l.name == cur)
            .and_then(|l| l.origin.as_deref())
        {
            Some(o) => {
                depth += 1;
                cur = o;
            }
            None => break,
        }
    }
    depth
}

fn layer_warning(name: &str, layers: u32) -> Option<String> {
    (layers > MAX_SNAPSHOT_LAYERS)
        .then(|| format!("{name} has {layers} snapshot layers (more than {MAX_SNAPSHOT_LAYERS})"))
}

/// `pct` percent of `bytes`. lvs reports percentages to two decimals, so
/// this is only that precise.
fn percent_of(bytes: u64, pct: f64) -> u64 {
    ((bytes as f64) * pct / 100.0).round() as u64
}

fn summarize(
    vg: &str,
    pool: Option<&str>,
    lvs: &[Lv],
    vg_bytes: u64,
    vg_free: u64,
) -> Result<Utilization> {
    let mut max_layers = 0;
    let mut warnings = Vec::new();
    for l in lvs {
        let n = layers(lvs, &l.name);
        max_layers = max_layers.max(n);
        warnings.extend(layer_warning(&l.name, n));
    }
    let volumes = lvs.iter().filter(|l| is_volume_id(&l.name)).count();
    let mut u = Utilization {
        vg: vg.to_string(),
        thin_pool: pool.map(str::to_string),
        bytes: vg_bytes,
        used_bytes: vg_bytes.saturating_sub(vg_free),
        free_bytes: vg_free,
        data_percent: 0.0,
        metadata_percent: None,
        metadata_bytes: None,
        provisioned_bytes: vg_bytes.saturating_sub(vg_free),
        vg_bytes,
        vg_free_bytes: vg_free,
        volumes,
        max_layers,
        warnings,
        reexport: None,
    };
    if let Some(pool) = pool {
        let p = lvs
            .iter()
            .find(|l| l.name == pool && l.segtype == "thin-pool")
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("no thin pool {vg}/{pool}")))?;
        let pct = p.data_percent.ok_or_else(|| {
            Error::other(format!(
                "thin pool {vg}/{pool} reports no usage (inactive?)"
            ))
        })?;
        u.bytes = p.bytes;
        u.used_bytes = percent_of(p.bytes, pct).min(p.bytes);
        u.free_bytes = p.bytes - u.used_bytes;
        u.data_percent = pct;
        u.metadata_percent = p.metadata_percent;
        u.metadata_bytes = p.metadata_bytes;
        u.provisioned_bytes = lvs
            .iter()
            .filter(|l| l.segtype == "thin" && l.pool.as_deref() == Some(pool))
            .map(|l| l.bytes)
            .sum();
    } else if u.bytes > 0 {
        u.data_percent = ((u.used_bytes as f64) * 10000.0 / (u.bytes as f64)).round() / 100.0;
    }
    Ok(u)
}

/// `client` is what the fence allows right now; if nft cannot be asked
/// (no table yet) the recorded `abe_client` tag stands in.
fn list_volumes() -> Result<Vec<Volume>> {
    let lvs = list_lvs()?;
    let traddr = advertised_traddr();
    let fence = match fence_list() {
        Ok(f) => Some(f),
        Err(e) => {
            warn!("cannot list the fence: {e}");
            None
        }
    };
    let mut vols = Vec::new();
    for l in lvs.iter().filter(|l| is_volume_id(&l.name)) {
        let n = layers(&lvs, &l.name);
        let port = existing_export(&l.name);
        let client = match (&fence, port.as_deref().and_then(|p| p.parse::<u16>().ok())) {
            (_, None) => None,
            (Some(f), Some(p)) => f.get(&p).map(|ip| ip.to_string()),
            (None, Some(_)) => tag_value(&l.tags, TAG_CLIENT).map(str::to_string),
        };
        vols.push(Volume {
            id: l.name.clone(),
            bytes: l.bytes,
            port,
            traddr: traddr.clone(),
            nqn: l.name.clone(),
            used_bytes: if l.segtype == "thin" {
                l.data_percent.map(|p| percent_of(l.bytes, p).min(l.bytes))
            } else {
                Some(l.bytes)
            },
            data_percent: l.data_percent,
            origin: l.origin.clone(),
            layers: n,
            warning: layer_warning(&l.name, n),
            base: tag_value(&l.tags, TAG_BASE).map(str::to_string),
            sealed: has_tag(&l.tags, TAG_SEALED),
            name: tag_value(&l.tags, TAG_NAME).map(str::to_string),
            client,
        });
    }
    Ok(vols)
}

/// udev creates a device-mapper partition map (abe-<id>p1) for the GPT
/// partition on the LV; it holds the LV open and makes lvremove fail with
/// "used by another device". Remove any such holders.
fn remove_holders(lv: &str) -> Result<()> {
    let dm = fs::canonicalize(lv)?;
    let dm = dm
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_string();
    let holders = match fs::read_dir(format!("/sys/block/{dm}/holders")) {
        Ok(h) => h,
        Err(_) => return Ok(()),
    };
    for h in holders.flatten() {
        let name = fs::read_to_string(h.path().join("dm/name"))?
            .trim()
            .to_string();
        info!("removing holder {name}");
        check(
            Command::new("/usr/sbin/dmsetup")
                .args(["remove", "--retry", &name])
                .output()?,
            "dmsetup remove",
        )?;
    }
    Ok(())
}

/// Tear down the nvmet port + subsystem for `id`, closing the fence for
/// its port first. Returns the trsvcid the volume was exported on, if any.
/// Missing pieces are not errors.
fn remove_export(id: &str) -> Result<Option<String>> {
    let root = nvmet_path();
    let mut svc = None;
    if let Ok(ports) = fs::read_dir(format!("{root}/ports")) {
        for p in ports.flatten() {
            let link = p.path().join("subsystems").join(id);
            if !link.exists() {
                continue;
            }
            svc = fs::read_to_string(p.path().join("addr_trsvcid"))
                .ok()
                .map(|s| s.trim().to_string());
            // Fence first: nobody reaches a port that is being torn down,
            // and a stale element can never outlive its export.
            if let Some(port) = svc.as_deref().and_then(|s| s.parse::<u16>().ok()) {
                if let Err(e) = fence_forget_port(port) {
                    warn!("could not close {port} in the fence: {e}");
                }
            }
            info!("unlinking {}", link.display());
            fs::remove_file(&link)?;
            // Drop the port too if nothing else is exported through it.
            let empty = fs::read_dir(p.path().join("subsystems"))
                .map(|mut d| d.next().is_none())
                .unwrap_or(false);
            if empty {
                info!("removing port {}", p.path().display());
                fs::remove_dir(p.path())?;
            }
        }
    }
    let subsys = PathBuf::from(format!("{root}/subsystems/{id}"));
    if subsys.exists() {
        if let Ok(nss) = fs::read_dir(subsys.join("namespaces")) {
            for ns in nss.flatten() {
                let _ = write(ns.path().join("enable"), "0");
                info!("removing namespace {}", ns.path().display());
                fs::remove_dir(ns.path())?;
            }
        }
        info!("removing subsystem {}", subsys.display());
        fs::remove_dir(&subsys)?;
    }
    Ok(svc)
}

/// If `id` is already exported, return the port it is exported on.
fn existing_export(id: &str) -> Option<String> {
    let ports = fs::read_dir(format!("{}/ports", nvmet_path())).ok()?;
    for p in ports.flatten() {
        if p.path().join("subsystems").join(id).exists() {
            let svc = fs::read_to_string(p.path().join("addr_trsvcid")).ok()?;
            return Some(svc.trim().to_string());
        }
    }
    None
}

/// Every trsvcid in use under `root/ports/*`. Port directory names are
/// opaque (older abe versions numbered them 1, 2, ...); only
/// `addr_trsvcid` counts. Entries that do not parse are logged and skipped.
fn used_ports(root: &Path) -> BTreeSet<u16> {
    let mut used = BTreeSet::new();
    let Ok(ports) = fs::read_dir(root.join("ports")) else {
        return used;
    };
    for p in ports.flatten() {
        let f = p.path().join("addr_trsvcid");
        match fs::read_to_string(&f) {
            Ok(s) => match s.trim().parse::<u16>() {
                Ok(n) => {
                    used.insert(n);
                }
                Err(_) => warn!(
                    "{}: trsvcid {:?} is not a port number",
                    f.display(),
                    s.trim()
                ),
            },
            Err(e) => warn!("{}: {e}", f.display()),
        }
    }
    used
}

/// The nvmet port range: ABE_PORT_MIN (default 44001) to ABE_PORT_MAX
/// (default 44999). Err(message) if it does not satisfy
/// `1 <= min <= max <= 65535`; main refuses to start on that.
fn port_range() -> std::result::Result<(u16, u16), String> {
    let get = |k: &str, d: u16| -> std::result::Result<u16, String> {
        match var(k) {
            Err(_) => Ok(d),
            Ok(s) if s.is_empty() => Ok(d),
            Ok(s) => s
                .trim()
                .parse::<u16>()
                .map_err(|e| format!("{k}={s:?} is not a port number (1-65535): {e}")),
        }
    };
    let (min, max) = (get("ABE_PORT_MIN", 23000)?, get("ABE_PORT_MAX", 23999)?);
    if min == 0 {
        return Err("ABE_PORT_MIN must be at least 1".to_string());
    }
    if min > max {
        return Err(format!("ABE_PORT_MIN={min} is above ABE_PORT_MAX={max}"));
    }
    Ok((min, max))
}

/// `port_range()` after main has validated it.
fn port_bounds() -> (u16, u16) {
    port_range().unwrap_or((23000, 23999))
}

/// The lowest port in `min..=max` that is not in `used`.
fn lowest_free(used: &BTreeSet<u16>, min: u16, max: u16) -> Option<u16> {
    (min..=max).find(|p| !used.contains(p))
}

/// Under OPS: the port the next export goes on. 503 when the range is
/// full.
fn pick_port() -> Res<u16> {
    let (min, max) = port_bounds();
    let used = used_ports(Path::new(&nvmet_path()));
    lowest_free(&used, min, max).ok_or_else(|| {
        Fail::new(
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "no free nvmet port in {min}-{max} ({} exported)",
                used.len()
            ),
        )
    })
}

/// Under OPS: export the LV `id` on `port`: subsystem, namespace, port
/// directory, link. If any step after the subsystem directory exists
/// fails, the export is torn down again before the error is returned, so
/// a failed export leaves no configfs junk behind.
fn export(id: &str, port: u16) -> Result<Message> {
    info!("exporting {id} on port {port}");
    let lv_path = lv_path_for_uuid(id);
    let steps = || -> Result<()> {
        let target = Subsystem::create(id)?;
        target.add_namespace("1", &lv_path)?;
        let p = Port::create(port, "tcp")?;
        p.link_subsystem(&target)?;
        Ok(())
    };
    if let Err(e) = steps() {
        warn!("export of {id} on {port} failed: {e}; cleaning up");
        if let Err(e2) = remove_export(id) {
            warn!("cleanup of {id} failed too: {e2}");
        }
        return Err(e);
    }
    Ok(Message::exported(id, &port.to_string()))
}

// NVME over TCP target subsystem
struct Subsystem {
    name: String,
}
impl Subsystem {
    fn create(name: &str) -> Result<Self> {
        let path = format!("{}/subsystems/{}", nvmet_path(), name);

        info!("making nvmet subsystem dir");
        fs::create_dir_all(&path)?;

        info!("allowing any host");
        fs::write(format!("{}/attr_allow_any_host", path), "1")?;
        Ok(Self {
            name: name.to_string(),
        })
    }
    fn add_namespace(&self, nsid: &str, device_path: &str) -> Result<()> {
        let ns_path = format!(
            "{}/subsystems/{}/namespaces/{}",
            nvmet_path(),
            self.name,
            nsid
        );
        info!("making namespace {ns_path}");
        fs::create_dir_all(&ns_path)?;

        info!("adding device {device_path}");
        File::create(format!("{}/device_path", ns_path))?.write_all(device_path.as_bytes())?;

        // Stable identity for initiators: udev turns this into
        // /dev/disk/by-id/nvme-uuid.<dashed id>, which survives reconnects
        // and reboots (unlike /dev/nvmeXnY).
        if let Some(u) = dashed_uuid(&self.name) {
            info!("setting device_uuid {u}");
            File::create(format!("{}/device_uuid", ns_path))?.write_all(u.as_bytes())?;
        }

        info!("enabling {ns_path}/enable");
        File::create(format!("{}/enable", ns_path))?.write_all(b"1")?;
        Ok(())
    }
}

// NVME over TCP port. The configfs directory is named after the port
// number itself (`ports/44003`); nvmet port ids are u16 so they fit.
struct Port {
    traddr: String,
    trsvcid: String,
    dir: PathBuf,
}
impl Port {
    fn create(port: u16, trtype: &str) -> Result<Port> {
        let dir = PathBuf::from(format!("{}/ports/{port}", nvmet_path()));
        if dir.exists() {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                format!("{} already exists", dir.display()),
            ));
        }
        info!("making port {}", dir.display());
        // nvmet-tcp accepts 0.0.0.0 to listen on every interface; override
        // with ABE_TRADDR to pin a specific one.
        let traddr: String = bind_traddr();
        let trsvcid: String = port.to_string();
        fs::create_dir_all(&dir)?;
        info!("writing addr_traddr {traddr}");
        File::create(dir.join("addr_traddr"))?.write_all(traddr.as_bytes())?;

        info!("writing addr_trsvcid {trsvcid}");
        File::create(dir.join("addr_trsvcid"))?.write_all(trsvcid.as_bytes())?;

        info!("writing addr_trtype {trtype}");
        File::create(dir.join("addr_trtype"))?.write_all(trtype.as_bytes())?;

        info!("writing addr_adrfam ipv4");
        File::create(dir.join("addr_adrfam"))?.write_all("ipv4".as_bytes())?;
        Ok(Port {
            traddr,
            trsvcid,
            dir,
        })
    }

    /// Link the subsystem into the port, which is what makes nvmet listen.
    fn link_subsystem(&self, subsystem: &Subsystem) -> Result<()> {
        let subsys_path = format!("{}/subsystems/{}", nvmet_path(), subsystem.name);
        let link = self.dir.join("subsystems").join(&subsystem.name);
        info!(
            "linking {} -> {subsys_path} ({}:{})",
            link.display(),
            self.traddr,
            self.trsvcid
        );
        symlinkat(subsys_path.as_str(), None, &link)?;
        Ok(())
    }
}

fn ensure_configfs_mounted() -> Result<()> {
    //fixme this doens't work

    info!("Mounting configfs...");
    if !Path::new(CONFIGFS_PATH).exists() {
        mount::<str, str, str, str>(
            Some("none"),
            CONFIGFS_PATH,
            Some("configfs"),
            MsFlags::empty(),
            None,
        )
        .expect("mount failed");
    }
    Ok(())
}

fn lv_path_for_uuid(uuid: &str) -> String {
    format!("/dev/{}/{uuid}", vg_name())
}

fn ensure_nvmet_present() -> Result<()> {
    info!("making nvmet subsystem");
    if !Path::new(&nvmet_path()).exists() {
        Command::new("modprobe")
            .args(["nvmet"])
            .output()
            .expect("modprobe failed");
    }
    Ok(())
}

pub fn create_lv(name: &str, size: &str, raw: bool) -> Result<()> {
    let vg = vg_name();
    let output = match thin_pool() {
        Some(pool) => {
            info!("making thin lv {name} in {vg}/{pool}");
            Command::new("/usr/sbin/lvcreate")
                .args([
                    "-y",
                    "-W",
                    "y",
                    "-V",
                    size,
                    "-T",
                    &format!("{vg}/{pool}"),
                    "-n",
                    name,
                ])
                .output()?
        }
        None => {
            info!("making lv {name} in {vg}");
            Command::new("/usr/sbin/lvcreate")
                .args(["-y", "-W", "y", "-L", size, "-n", name, &vg])
                .output()?
        }
    };

    check(output, "lvcreate")?;
    let dev = lv_path_for_uuid(name);
    if raw {
        info!("created {dev} ({size}), left blank");
        return Ok(());
    }
    // One GPT partition labelled with the volume id so initiators can find
    // it by PARTLABEL. The partition is left blank: the client decides on
    // encryption and filesystem.
    info!("partitioning {dev}");
    check(
        Command::new("/usr/sbin/parted")
            .args(["-s", &dev, "mklabel", "gpt"])
            .output()?,
        "parted mklabel",
    )?;
    check(
        Command::new("/usr/sbin/parted")
            .args(["-s", &dev, "mkpart", "primary", "1MiB", "100%"])
            .output()?,
        "parted mkpart",
    )?;
    check(
        Command::new("/usr/sbin/parted")
            .args(["-s", &dev, "name", "1", name])
            .output()?,
        "parted name",
    )?;
    info!("created {dev} ({size})");
    Ok(())
}

fn check(output: std::process::Output, what: &str) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
    warn!("{what} failed: {err}");
    Err(Error::other(format!("{what} failed: {err}")))
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let (port_min, port_max) = match port_range() {
        Ok(r) => r,
        Err(e) => {
            error!("bad port range: {e}");
            std::process::exit(2);
        }
    };

    // Listen address and TLS material are checked first: a typo in
    // /etc/default/abe fails here, before nvmet, the fence or the port
    // reservation have been touched.
    let listen = listen_config();

    if let Err(e) = ensure_configfs_mounted().and_then(|_| ensure_nvmet_present()) {
        error!("cannot set up nvmet: {e}");
        std::process::exit(1);
    }

    warn_if_discards_ignored();
    reserve_ports(Path::new(RESERVED_PORTS), port_min, port_max);

    // The fence goes up before anything is exported, already holding the
    // exports that survived the restart (to their recorded or adopted
    // clients), so no port is ever reachable from everywhere.
    if let Err(e) = tokio::task::spawn_blocking(|| with_ops(fence_rebuild))
        .await
        .unwrap_or_else(|e| Err(Error::other(e.to_string())))
    {
        error!("cannot install the nvmet fence (nft): {e}");
        std::process::exit(4);
    }

    // Everything exported before the restart comes back before the first
    // request can be served, so nobody sees a half-restored target.
    reexport_at_startup().await;

    let app = Router::new()
        .route("/id/:id", get(attach).delete(detach))
        .route("/configure", get(configure))
        .route("/clone/:id", get(clone_volume))
        .route("/volumes", get(volumes))
        .route("/utilization", get(utilization))
        .route("/reexport", get(reexport))
        .route("/seal/:id", get(seal))
        .route("/version", get(version));

    info!(
        "vg={} thin_pool={:?} bind={} advertise={} nvmet={} ports={port_min}-{port_max} nft={} tls={}",
        vg_name(),
        thin_pool(),
        bind_traddr(),
        advertised_traddr(),
        nvmet_path(),
        nft_bin().display(),
        tls_enabled()
    );
    serve(app, listen).await;
}

/// What `serve` needs, resolved by `listen_config` before startup side
/// effects: the bound address and the TLS server config (None = ABE_TLS=off).
struct Listen {
    addr: SocketAddr,
    tls: Option<Arc<rustls::ServerConfig>>,
}

/// Parse ABE_LISTEN and load the TLS material (ABE_TLS=on); exits 2 on a bad
/// address and 3 when the cert/key/CA cannot be loaded, having changed
/// nothing on the host.
fn listen_config() -> Listen {
    let addr: SocketAddr = match listen_addr().parse() {
        Ok(a) => a,
        Err(e) => {
            error!("ABE_LISTEN={:?}: {e}", listen_addr());
            std::process::exit(2);
        }
    };
    let tls = if tls_enabled() {
        match tls_config() {
            Ok(c) => Some(c),
            Err(e) => {
                error!("cannot load the TLS configuration: {e}");
                std::process::exit(3);
            }
        }
    } else {
        warn!("ABE_TLS=off: the API is served over plain HTTP without authentication");
        None
    };
    Listen { addr, tls }
}

/// Serve `app` on the address from `listen_config` over mutual TLS (or plain
/// HTTP with ABE_TLS=off) until the process ends. Handlers get the peer
/// address in both modes.
async fn serve(app: Router, listen: Listen) {
    let Listen { addr, tls } = listen;
    let scheme = if tls.is_some() { "https" } else { "http" };
    let shown = if addr.ip().is_unspecified() {
        get_if_addrs()
            .map(|addrs| {
                addrs
                    .into_iter()
                    .filter(|i| i.ip().is_ipv4() && !i.is_loopback())
                    .map(|i| i.ip().to_string())
                    .collect()
            })
            .unwrap_or_default()
    } else {
        vec![addr.ip().to_string()]
    };
    for ip in shown {
        println!("Listening on {scheme}://{ip}:{}", addr.port());
    }
    let svc = app.into_make_service_with_connect_info::<SocketAddr>();
    let r = match tls {
        Some(cfg) => {
            axum_server::bind_rustls(addr, RustlsConfig::from_config(cfg))
                .serve(svc)
                .await
        }
        None => axum_server::bind(addr).serve(svc).await,
    };
    if let Err(e) = r {
        error!("serving {scheme}://{addr}: {e}");
        std::process::exit(5);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // What `lvs --noheadings --units b --nosuffix --separator '|' -o LVS_FIELDS`
    // prints: a thick LV, a thin pool, a base image, two abe volumes (the
    // second a clone of the first, both tagged) and an inactive snapshot.
    const LVS: &str = "\
  root|99996401664||||||linear||active
  abe|1398887514112|||12.34|10.50|2147483648|thin-pool||active
  base-xdebbie-base|10737418240|abe||25.00|||thin||active
  0123456789abcdef0123456789abcdef|42949672960|abe|base-xdebbie-base|50.00|||thin|abe_port=44001,abe_name=vol-a|active
  fedcba9876543210fedcba9876543210|42949672960|abe|0123456789abcdef0123456789abcdef|0.00|||thin|abe_port=44002|active
  parked|10737418240|abe|[gone]||||thin||
";

    #[test]
    fn clone_reply_of_an_existing_volume_has_one_bytes_key() {
        // A retried /clone hands back the existing export, whose Message
        // carries `bytes`; the reply's own `bytes` must be the only one.
        let mut export = Message::exported("3adcceb82a964a248987646ebc7c8c4b", "23000");
        export.bytes = Some(21474836480);
        export.existing = true;
        let r = CloneReply::new(export, 21474836480, "48744e68".to_string(), 1, None);
        let js = serde_json::to_string(&r).unwrap();
        assert_eq!(js.matches("\"bytes\"").count(), 1, "{js}");
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct Strict {
            id: String,
            port: String,
            existing: bool,
            bytes: u64,
            origin: String,
            layers: u32,
        }
        let s: Strict = serde_json::from_str(&js).unwrap();
        assert!(s.existing);
        assert_eq!(s.bytes, 21474836480);
    }

    fn thin(name: &str, origin: Option<&str>) -> Lv {
        Lv {
            name: name.to_string(),
            bytes: 1 << 30,
            pool: Some("abe".to_string()),
            origin: origin.map(str::to_string),
            data_percent: Some(0.0),
            metadata_percent: None,
            metadata_bytes: None,
            segtype: "thin".to_string(),
            tags: Vec::new(),
            active: true,
        }
    }

    /// v0, v1 cloned from v0, ... v<n> cloned from v<n-1>.
    fn chain(n: usize) -> Vec<Lv> {
        let mut lvs = vec![thin("v0", None)];
        for i in 1..=n {
            lvs.push(thin(&format!("v{i}"), Some(&format!("v{}", i - 1))));
        }
        lvs
    }

    #[test]
    fn parses_lvs() {
        let lvs = parse_lvs(LVS);
        assert_eq!(lvs.len(), 6);
        assert_eq!(
            lvs[0],
            Lv {
                name: "root".into(),
                bytes: 99996401664,
                pool: None,
                origin: None,
                data_percent: None,
                metadata_percent: None,
                metadata_bytes: None,
                segtype: "linear".into(),
                tags: vec![],
                active: true,
            }
        );
        assert_eq!(lvs[1].segtype, "thin-pool");
        assert_eq!(lvs[1].data_percent, Some(12.34));
        assert_eq!(lvs[1].metadata_percent, Some(10.5));
        assert_eq!(lvs[1].metadata_bytes, Some(2147483648));
        assert_eq!(lvs[3].pool.as_deref(), Some("abe"));
        assert_eq!(lvs[3].origin.as_deref(), Some("base-xdebbie-base"));
        assert_eq!(lvs[5].origin.as_deref(), Some("gone"));
        assert_eq!(lvs[5].data_percent, None);
        // tags: none, one, several; active: yes, and the parked snapshot no
        assert!(lvs[2].tags.is_empty());
        assert_eq!(
            lvs[3].tags,
            vec!["abe_port=44001".to_string(), "abe_name=vol-a".to_string()]
        );
        assert_eq!(lvs[4].tags, vec!["abe_port=44002".to_string()]);
        assert!(lvs[3].active);
        assert!(!lvs[5].active);
    }

    #[test]
    fn parses_lvs_without_the_tag_columns() {
        // output of an older LVS_FIELDS (or a short fixture) still parses
        let lvs = parse_lvs("  root|99996401664||||||linear\n");
        assert_eq!(lvs.len(), 1);
        assert!(lvs[0].tags.is_empty());
        assert!(lvs[0].active);
    }

    #[test]
    fn reads_tags() {
        let tags: Vec<String> = ["abe_port=44001", "abe_name=vol-a", "abe_sealed", "other"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(tag_value(&tags, "abe_port"), Some("44001"));
        assert_eq!(tag_value(&tags, "abe_name"), Some("vol-a"));
        assert_eq!(tag_value(&tags, "abe_base"), None);
        assert_eq!(tag_value(&tags, "abe_sealed"), None);
        assert!(has_tag(&tags, "abe_sealed"));
        assert!(has_tag(&tags, "abe_port"));
        assert!(has_tag(&tags, "other"));
        assert!(!has_tag(&tags, "abe_base"));
        assert!(!has_tag(&tags, "abe"));
        assert!(!has_tag(&[], "abe_sealed"));
        let lvs = parse_lvs(LVS);
        assert_eq!(
            find_tagged(&lvs, "abe_name=vol-a").map(|l| l.name.as_str()),
            Some("0123456789abcdef0123456789abcdef")
        );
        assert!(find_tagged(&lvs, "abe_name=vol-b").is_none());
        // only abe volumes count, whatever they are tagged
        assert!(find_tagged(&lvs, "abe_port=44001").is_some());
    }

    #[test]
    fn validates_names_and_images() {
        for ok in [
            "a",
            "vol-x",
            "vm-0123-root",
            "debian-12.5+cloud:amd64",
            "a_b",
            &"x".repeat(128),
        ] {
            assert!(valid_tag_value(ok), "{ok:?} should be accepted");
        }
        for bad in [
            "",
            " ",
            "a b",
            "a/b",
            "a=b",
            "a,b",
            "ü",
            "a\n",
            &"x".repeat(129),
            "a@b",
            "a#b",
        ] {
            assert!(!valid_tag_value(bad), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn parses_lv_sizes() {
        assert_eq!(parse_lv_size("10G"), Some(10 << 30));
        assert_eq!(parse_lv_size("512M"), Some(512 << 20));
        assert_eq!(parse_lv_size("512"), Some(512 << 20));
        assert_eq!(parse_lv_size("1T"), Some(1 << 40));
        assert_eq!(parse_lv_size("64MiB"), Some(64 << 20));
        assert_eq!(parse_lv_size("4k"), Some(4096));
        assert_eq!(parse_lv_size("2GB"), Some(2 << 30));
        assert_eq!(parse_lv_size(""), None);
        assert_eq!(parse_lv_size("abc"), None);
        assert_eq!(parse_lv_size("10X"), None);
    }

    #[test]
    fn picks_the_lowest_free_port() {
        let used = |v: &[u16]| v.iter().copied().collect::<BTreeSet<u16>>();
        assert_eq!(lowest_free(&used(&[]), 44001, 44999), Some(44001));
        // a gap left by a delete is filled before anything higher
        assert_eq!(
            lowest_free(&used(&[44001, 44003]), 44001, 44999),
            Some(44002)
        );
        assert_eq!(
            lowest_free(&used(&[44001, 44002, 44003]), 44001, 44999),
            Some(44004)
        );
        // ports outside the range do not matter
        assert_eq!(
            lowest_free(&used(&[1, 2, 65535]), 44001, 44002),
            Some(44001)
        );
        // full
        assert_eq!(lowest_free(&used(&[44001, 44002]), 44001, 44002), None);
        // one-port range
        assert_eq!(lowest_free(&used(&[]), 44001, 44001), Some(44001));
        assert_eq!(lowest_free(&used(&[44001]), 44001, 44001), None);
        // the ends of u16 do not overflow
        assert_eq!(lowest_free(&used(&[65535]), 65535, 65535), None);
        assert_eq!(lowest_free(&used(&[]), 65534, 65535), Some(65534));
    }

    /// A fresh directory under the system temp dir, removed on drop.
    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> TempDir {
            let d = std::env::temp_dir().join(format!("abe-test-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&d);
            fs::create_dir_all(&d).unwrap();
            TempDir(d)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn scans_used_ports() {
        let t = TempDir::new("ports");
        // no ports directory at all
        assert!(used_ports(&t.0).is_empty());
        // old-style small directory names and new port-named ones, one
        // unparseable entry and one without the attribute
        for (dir, svc) in [
            ("1", "44001\n"),
            ("2", "44003"),
            ("44002", "44002\n"),
            ("7", "bogus"),
        ] {
            let d = t.0.join("ports").join(dir);
            fs::create_dir_all(&d).unwrap();
            fs::write(d.join("addr_trsvcid"), svc).unwrap();
        }
        fs::create_dir_all(t.0.join("ports").join("9")).unwrap();
        let used = used_ports(&t.0);
        assert_eq!(
            used.into_iter().collect::<Vec<_>>(),
            vec![44001, 44002, 44003]
        );
    }

    #[test]
    fn skips_garbage_lines() {
        assert!(parse_lvs("").is_empty());
        assert!(parse_lvs("  WARNING: something\n\n  a|b\n  x|notanumber||||||thin\n").is_empty());
    }

    #[test]
    fn parses_vgs() {
        assert_eq!(
            parse_vgs("  1999307276288|599785537536\n"),
            Some((1999307276288, 599785537536))
        );
        assert_eq!(parse_vgs(""), None);
        assert_eq!(parse_vgs("  1.82t|558g\n"), None);
    }

    #[test]
    fn counts_layers() {
        let lvs = parse_lvs(LVS);
        assert_eq!(layers(&lvs, "root"), 0);
        assert_eq!(layers(&lvs, "base-xdebbie-base"), 0);
        assert_eq!(layers(&lvs, "0123456789abcdef0123456789abcdef"), 1);
        assert_eq!(layers(&lvs, "fedcba9876543210fedcba9876543210"), 2);
        // the origin is named but no longer in the report: still one layer
        assert_eq!(layers(&lvs, "parked"), 1);
        assert_eq!(layers(&lvs, "nonexistent"), 0);
    }

    #[test]
    fn layer_count_survives_a_loop() {
        let lvs = vec![thin("a", Some("b")), thin("b", Some("a"))];
        assert_eq!(layers(&lvs, "a"), 2);
    }

    #[test]
    fn warns_only_past_ten_layers() {
        let lvs = chain(11);
        assert_eq!(layers(&lvs, "v10"), 10);
        assert_eq!(layer_warning("v10", layers(&lvs, "v10")), None);
        assert_eq!(layers(&lvs, "v11"), 11);
        assert_eq!(
            layer_warning("v11", layers(&lvs, "v11")).as_deref(),
            Some("v11 has 11 snapshot layers (more than 10)")
        );
    }

    #[test]
    fn a_clone_of_the_tenth_layer_is_the_first_to_warn() {
        // what clone_volume computes before it creates anything
        let lvs = chain(10);
        assert_eq!(layer_warning("new", layers(&lvs, "v9") + 1), None);
        assert!(layer_warning("new", layers(&lvs, "v10") + 1).is_some());
    }

    #[test]
    fn summarizes_a_thin_pool() {
        let lvs = parse_lvs(LVS);
        let u = summarize(
            "timesink-vg",
            Some("abe"),
            &lvs,
            1999307276288,
            599785537536,
        )
        .unwrap();
        assert_eq!(u.bytes, 1398887514112);
        assert_eq!(u.used_bytes, 172622719241); // 12.34 %
        assert_eq!(u.free_bytes, 1398887514112 - 172622719241);
        assert_eq!(u.data_percent, 12.34);
        assert_eq!(u.metadata_percent, Some(10.5));
        assert_eq!(u.metadata_bytes, Some(2147483648));
        // base + two volumes + parked; not root, not the pool itself
        assert_eq!(
            u.provisioned_bytes,
            10737418240 + 2 * 42949672960 + 10737418240
        );
        assert_eq!(u.vg_bytes, 1999307276288);
        assert_eq!(u.vg_free_bytes, 599785537536);
        assert_eq!(u.volumes, 2);
        assert_eq!(u.max_layers, 2);
        assert!(u.warnings.is_empty());
    }

    #[test]
    fn summarizes_a_plain_vg() {
        let lvs = parse_lvs("  0123456789abcdef0123456789abcdef|1073741824||||||linear\n");
        let u = summarize("abe", None, &lvs, 4 << 30, 3 << 30).unwrap();
        assert_eq!(
            (u.bytes, u.used_bytes, u.free_bytes),
            (4 << 30, 1 << 30, 3 << 30)
        );
        assert_eq!(u.data_percent, 25.0);
        assert_eq!(u.metadata_percent, None);
        assert_eq!(u.volumes, 1);
    }

    #[test]
    fn summary_lists_deep_chains() {
        let mut lvs = chain(12);
        lvs.push(Lv {
            name: "abe".into(),
            segtype: "thin-pool".into(),
            pool: None,
            ..thin("abe", None)
        });
        let u = summarize("abe", Some("abe"), &lvs, 1 << 40, 0).unwrap();
        assert_eq!(u.max_layers, 12);
        assert_eq!(
            u.warnings,
            vec![
                "v11 has 11 snapshot layers (more than 10)".to_string(),
                "v12 has 12 snapshot layers (more than 10)".to_string(),
            ]
        );
    }

    #[test]
    fn summary_fails_without_its_pool() {
        let lvs = parse_lvs(LVS);
        assert!(summarize("timesink-vg", Some("abe-pool"), &lvs, 1, 1).is_err());
        // an LV of that name that is not a pool does not count
        assert!(summarize("timesink-vg", Some("root"), &lvs, 1, 1).is_err());
    }

    #[test]
    fn parses_fio_json() {
        let json = r#"{"fio version": "fio-3.33", "jobs": [{"jobname": "abe", "write": {
            "io_bytes": 104857600, "bw_bytes": 20480000, "bw": 20000, "iops": 5000.0,
            "runtime": 5004, "clat_ns": {"min": 90000, "max": 3000000, "mean": 187456.7}}}]}"#;
        let p = parse_fio(json, "4k", 1).unwrap();
        assert_eq!(p.bs, "4k");
        assert_eq!(p.iodepth, 1);
        assert_eq!(p.seconds, 5.0);
        assert_eq!(p.write_mib_s, 19.53);
        assert_eq!(p.write_iops, 5000.0);
        assert_eq!(p.write_lat_us, 187.46);
    }

    #[test]
    fn fio_region_stays_inside_partition_one() {
        // raw: from the start, capped at a GiB, whole MiBs
        assert_eq!(
            fio_region(64 * MIB, true),
            Some(Region {
                offset: 0,
                len: 64 * MIB
            })
        );
        assert_eq!(
            fio_region(GIB, true),
            Some(Region {
                offset: 0,
                len: GIB
            })
        );
        assert_eq!(
            fio_region(10 * GIB, true),
            Some(Region {
                offset: 0,
                len: GIB
            })
        );
        assert_eq!(
            fio_region(64 * MIB + 12345, true),
            Some(Region {
                offset: 0,
                len: 64 * MIB
            })
        );
        // non-raw: starts at 1 MiB, stops 1 MiB short of the end
        assert_eq!(
            fio_region(64 * MIB, false),
            Some(Region {
                offset: MIB,
                len: 62 * MIB
            })
        );
        assert_eq!(
            fio_region(10 * GIB, false),
            Some(Region {
                offset: MIB,
                len: GIB
            })
        );
        assert_eq!(
            fio_region(GIB + 2 * MIB, false),
            Some(Region {
                offset: MIB,
                len: GIB
            })
        );
        assert_eq!(
            fio_region(GIB + MIB + 1, false),
            Some(Region {
                offset: MIB,
                len: GIB - MIB
            })
        );
        // too small to bother
        assert_eq!(fio_region(0, true), None);
        assert_eq!(fio_region(4 * MIB, true), None);
        assert_eq!(fio_region(16 * MIB - 1, true), None);
        assert_eq!(fio_region(16 * MIB, true).map(|r| r.len), Some(16 * MIB));
        assert_eq!(fio_region(17 * MIB, false), None);
        assert_eq!(
            fio_region(18 * MIB, false),
            Some(Region {
                offset: MIB,
                len: 16 * MIB
            })
        );
        // alignment: the length is always a multiple of a MiB
        for b in [100 * MIB + 1, 777_777_777, 3 * GIB + 5] {
            for raw in [true, false] {
                let r = fio_region(b, raw).unwrap();
                assert_eq!(r.len % MIB, 0, "{b} raw={raw}");
                assert!(r.offset + r.len <= b);
            }
        }
    }

    #[test]
    fn parses_parted_partition_one() {
        let id = "0123456789abcdef0123456789abcdef";
        let text = format!(
            "BYT;\n/dev/abe/{id}:67108864B:dm:512:512:gpt:Linux device-mapper (thin):;\n1:1048576B:67091967B:66043392B::{id}:;\n"
        );
        assert_eq!(parse_parted_part1(&text), Some((MIB, id.to_string())));
        assert_eq!(
            parse_parted_part1("BYT;\n/dev/x:1B:dm:512:512:unknown:x:;\n"),
            None
        );
        assert_eq!(parse_parted_part1(""), None);
        // a partition that moved is not intact
        let moved = "1:2097152B:67091967B:64994816B::abc:;\n";
        assert_eq!(
            parse_parted_part1(moved),
            Some((2 * MIB, "abc".to_string()))
        );
    }

    #[test]
    fn perf_reports_trimmed() {
        let p = Perf {
            bs: "4k".into(),
            iodepth: 1,
            seconds: 5.0,
            write_mib_s: 1.0,
            write_iops: 1.0,
            write_lat_us: 1.0,
            trimmed: true,
        };
        let v: serde_json::Value = serde_json::to_value(&p).unwrap();
        assert_eq!(v["trimmed"], serde_json::Value::Bool(true));
        // an old reply without the field still parses
        let old: Perf = serde_json::from_str(
            r#"{"bs":"4k","iodepth":1,"seconds":5.0,"write_mib_s":1.0,"write_iops":1.0,"write_lat_us":1.0}"#,
        )
        .unwrap();
        assert!(!old.trimmed);
    }

    #[test]
    fn fio_without_results_is_none() {
        assert_eq!(parse_fio("", "4k", 1), None);
        assert_eq!(parse_fio(r#"{"jobs": []}"#, "4k", 1), None);
        assert_eq!(
            parse_fio(r#"{"jobs": [{"read": {"bw_bytes": 1}}]}"#, "4k", 1),
            None
        );
    }

    #[test]
    fn recognises_volume_ids() {
        assert!(is_volume_id("0123456789abcdef0123456789abcdef"));
        assert!(!is_volume_id("base-xdebbie-base"));
        assert!(!is_volume_id("0123456789abcdef0123456789abcde"));
        assert!(!is_volume_id("0123456789abcdef0123456789abcdeg"));
    }

    // ---- TLS --------------------------------------------------------------

    /// tests/certs/<name>: the committed test-only PKI (see README.txt there).
    fn cert(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/certs")
            .join(name)
    }

    #[test]
    fn tls_config_loads_the_test_pki() {
        let cfg = tls_config_from(
            &cert("server.pem"),
            &cert("server-key.pem"),
            &cert("ca.pem"),
        );
        assert!(cfg.is_ok(), "{:?}", cfg.err());
        // every failure names the file that is wrong
        for (c, k, ca) in [
            ("missing.pem", "server-key.pem", "ca.pem"),
            ("server.pem", "missing-key.pem", "ca.pem"),
            ("server.pem", "server-key.pem", "missing-ca.pem"),
            ("server.pem", "ca.pem", "ca.pem"), // no key in there
            ("server.pem", "other-ca-key.pem", "ca.pem"), // key does not match the cert
            ("README.txt", "server-key.pem", "ca.pem"), // no cert in there
        ] {
            let e = tls_config_from(&cert(c), &cert(k), &cert(ca)).unwrap_err();
            let msg = e.to_string();
            assert!(
                msg.contains("tests/certs/"),
                "{c} {k} {ca}: error does not name a path: {msg}"
            );
        }
    }

    #[test]
    fn client_verifier_wants_our_ca() {
        let client = read_pem_certs(&cert("client.pem")).unwrap().remove(0);
        let now = rustls::pki_types::UnixTime::now();
        let ours = client_verifier(&cert("ca.pem")).unwrap();
        assert!(ours.verify_client_cert(&client, &[], now).is_ok());
        assert!(ours.client_auth_mandatory(), "clients must present a cert");
        let theirs = client_verifier(&cert("other-ca.pem")).unwrap();
        assert!(theirs.verify_client_cert(&client, &[], now).is_err());
        let other = read_pem_certs(&cert("other-client.pem")).unwrap().remove(0);
        assert!(ours.verify_client_cert(&other, &[], now).is_err());
        assert!(theirs.verify_client_cert(&other, &[], now).is_ok());
    }

    #[test]
    fn version_reports_tls_and_fence() {
        let v: serde_json::Value = serde_json::to_value(version_info()).unwrap();
        assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
        assert!(v["tls"].is_boolean());
        let f = v["features"].as_array().unwrap();
        for want in ["reexport", "ports", "name", "trim", "tls", "fence"] {
            assert!(f.iter().any(|x| x == want), "feature {want} missing: {f:?}");
        }
    }

    /// A rustls client that trusts tests/certs/ca.pem, with or without the
    /// test client certificate.
    fn tls_client(with_cert: bool) -> tokio_rustls::TlsConnector {
        ensure_crypto_provider();
        let mut roots = rustls::RootCertStore::empty();
        for c in read_pem_certs(&cert("ca.pem")).unwrap() {
            roots.add(c).unwrap();
        }
        let b = rustls::ClientConfig::builder().with_root_certificates(roots);
        let cfg = if with_cert {
            b.with_client_auth_cert(
                read_pem_certs(&cert("client.pem")).unwrap(),
                read_pem_key(&cert("client-key.pem")).unwrap(),
            )
            .unwrap()
        } else {
            b.with_no_client_auth()
        };
        tokio_rustls::TlsConnector::from(Arc::new(cfg))
    }

    /// GET /version over TLS from the client `c`; the raw HTTP/1.1 reply.
    async fn tls_get_version(c: &tokio_rustls::TlsConnector, addr: SocketAddr) -> Result<String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let tcp = tokio::net::TcpStream::connect(addr).await?;
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut s = c.connect(name, tcp).await?;
        s.write_all(b"GET /version HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await?;
        let mut out = String::new();
        s.read_to_string(&mut out).await?;
        Ok(out)
    }

    #[tokio::test]
    async fn serves_version_only_to_clients_with_our_cert() {
        let cfg = tls_config_from(
            &cert("server.pem"),
            &cert("server-key.pem"),
            &cert("ca.pem"),
        )
        .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route("/version", get(version));
        let server = tokio::spawn(
            axum_server::from_tcp_rustls(listener, RustlsConfig::from_config(cfg))
                .serve(app.into_make_service_with_connect_info::<SocketAddr>()),
        );
        let reply = tls_get_version(&tls_client(true), addr).await.unwrap();
        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
        let body = reply.split("\r\n\r\n").nth(1).unwrap_or_default();
        let v: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
        assert!(v["features"].as_array().unwrap().iter().any(|f| f == "tls"));
        // without a client certificate the handshake is refused: no reply
        match tls_get_version(&tls_client(false), addr).await {
            Err(e) => assert!(
                e.to_string().to_lowercase().contains("certificate"),
                "unexpected error: {e}"
            ),
            Ok(r) => panic!("served without a client certificate: {r}"),
        }
        server.abort();
    }

    // ---- the fence --------------------------------------------------------

    const FENCE_SCRIPT: &str = "\
destroy table inet abe
table inet abe {
    set ports {
        type inet_service
        comment \"nvmet ports exported by abe\"
    }
    set allowed {
        type ipv4_addr . inet_service
        comment \"client ip . nvmet port opened by abe\"
    }
    chain input {
        type filter hook input priority filter - 10; policy accept;
        ip saddr . tcp dport @allowed  accept
        tcp dport @ports  tcp flags & (syn | ack) == syn  reject with tcp reset
        meta nfproto ipv6  tcp dport @ports  tcp flags & (syn | ack) == syn  reject with tcp reset
    }
}
";

    #[test]
    fn reserved_ports_update_appends_unless_covered() {
        assert_eq!(
            reserved_ports_update("", 44001, 44999).as_deref(),
            Some("44001-44999")
        );
        assert_eq!(
            reserved_ports_update("8080,9000-9100", 44001, 44999).as_deref(),
            Some("8080,9000-9100,44001-44999")
        );
        assert_eq!(reserved_ports_update("44001-44999", 44001, 44999), None);
        assert_eq!(
            reserved_ports_update("8080,44000-45000", 44001, 44999),
            None
        );
        assert_eq!(
            reserved_ports_update("44001-44500", 44001, 44999).as_deref(),
            Some("44001-44500,44001-44999")
        );
        // the kernel's own formatting (trailing newline) is tolerated
        assert_eq!(
            reserved_ports_update("44001-44999\n".trim(), 44001, 44999),
            None
        );
    }

    #[test]
    fn reserve_ports_writes_the_file() {
        let f = std::env::temp_dir().join(format!("abe-reserved-{}", std::process::id()));
        std::fs::write(&f, "8080\n").unwrap();
        reserve_ports(&f, 44001, 44999);
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "8080,44001-44999");
        reserve_ports(&f, 44001, 44999);
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "8080,44001-44999");
        let _ = std::fs::remove_file(&f);
    }

    #[test]
    fn fence_script_golden() {
        assert_eq!(fence_script_empty(), FENCE_SCRIPT);
        let with = fence_script(
            &[23000, 23001, 44001],
            &[
                ("10.22.0.1".parse().unwrap(), 23000),
                ("10.23.0.2".parse().unwrap(), 23001),
            ],
        );
        assert_eq!(
            with,
            FENCE_SCRIPT
                .replace(
                    "        comment \"nvmet ports exported by abe\"\n",
                    "        comment \"nvmet ports exported by abe\"\n        elements = { 23000, 23001, 44001 }\n",
                )
                .replace(
                    "        comment \"client ip . nvmet port opened by abe\"\n",
                    "        comment \"client ip . nvmet port opened by abe\"\n        elements = { 10.22.0.1 . 23000, 10.23.0.2 . 23001 }\n",
                )
        );
    }

    #[test]
    fn fence_script_loads_in_a_namespace() {
        let nft = ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"]
            .into_iter()
            .find(|p| Path::new(p).is_file());
        let (Some(nft), Ok(probe)) = (
            nft,
            Command::new("unshare").args(["-r", "-n", "true"]).output(),
        ) else {
            eprintln!("skipped: no nft or unshare");
            return;
        };
        if !probe.status.success() {
            eprintln!("skipped: unshare -r -n not permitted here");
            return;
        }
        let script = fence_script(&[44001], &[("10.22.0.1".parse().unwrap(), 44001)]);
        let one = |args: &[&str], stdin: &str| -> (bool, String) {
            let mut c = Command::new("unshare")
                .args(["-r", "-n", "sh", "-c"])
                .arg(format!(
                    "{nft} -f - && {nft} {} && {nft} -j list set inet abe allowed",
                    args.join(" ")
                ))
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            c.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
            let o = c.wait_with_output().unwrap();
            (
                o.status.success(),
                String::from_utf8_lossy(&o.stdout).into_owned()
                    + &String::from_utf8_lossy(&o.stderr),
            )
        };
        // install twice (destroy of an existing table) then open one more
        let (ok, out) = one(
            &[&format!(
                "add element inet abe ports '{{ 44002 }}' && {nft} add element inet abe ports '{{ 44002 }}' \
                 && {nft} add element inet abe allowed '{{ 10.23.0.2 . 44002 }}'"
            )],
            &format!("{script}{script}"),
        );
        assert!(ok, "{out}");
        let set = parse_nft_set_json(&out).unwrap();
        assert_eq!(
            set.get(&44001).map(|ip| ip.to_string()).as_deref(),
            Some("10.22.0.1")
        );
        assert_eq!(
            set.get(&44002).map(|ip| ip.to_string()).as_deref(),
            Some("10.23.0.2")
        );
        let (ok, out) = one(
            &[&format!(
                "delete element inet abe allowed '{{ 10.22.0.1 . 44001 }}' \
                 && {nft} delete element inet abe ports '{{ 44001 }}'"
            )],
            &script,
        );
        assert!(ok, "{out}");
        assert!(parse_nft_set_json(&out).unwrap().is_empty());
        // deleting a port that is not in the set is the error fence_forget_port tolerates
        let (ok, out) = one(&["delete element inet abe ports '{ 23000 }'"], &script);
        assert!(!ok && out.contains("No such file or directory"), "{out}");
    }

    #[test]
    fn parses_nft_set_json() {
        let json = r#"{"nftables":[{"metainfo":{"version":"1.1.7","release_name":"Commodore Bullmoose #8","json_schema_version":1}},{"set":{"family":"inet","name":"allowed","table":"abe","type":["ipv4_addr","inet_service"],"handle":2,"comment":"client ip . nvmet port opened by abe","elem":[{"concat":["10.22.0.1",44001]},{"concat":["10.23.0.2",44002]}]}}]}"#;
        let m = parse_nft_set_json(json).unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!(m[&44001], "10.22.0.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(m[&44002], "10.23.0.2".parse::<Ipv4Addr>().unwrap());
        // an empty set has no elem key at all
        let empty = r#"{"nftables":[{"metainfo":{}},{"set":{"family":"inet","name":"allowed","table":"abe","type":["ipv4_addr","inet_service"]}}]}"#;
        assert!(parse_nft_set_json(empty).unwrap().is_empty());
        assert!(parse_nft_set_json("not json").is_err());
        assert!(parse_nft_set_json("{}").is_err());
    }

    #[test]
    fn finds_established_peers() {
        // one established to 44001 from 10.22.0.1, one TIME_WAIT (06) to it
        // from 10.22.0.9, one established to 44002, and the listener
        let body = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100167F:ABE1 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n\
   1: 0101160A:ABE1 0100160A:C350 01 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 20 4 30 10 -1\n\
   2: 0101160A:ABE1 0900160A:C351 06 00000000:00000000 03:00000A1B 00000000     0        0 0 3 0000000000000000\n\
   3: 0101160A:ABE2 0200170A:C352 01 00000000:00000000 00:00000000 00000000     0        0 12347 1 0000000000000000 20 4 30 10 -1\n\
   4: 0101160A:ABE1 0100160A:C353 01 00000000:00000000 00:00000000 00000000     0        0 12348 1 0000000000000000 20 4 30 10 -1\n";
        let p = peers_on_port(body, 44001);
        assert_eq!(
            p.into_iter().collect::<Vec<_>>(),
            vec!["10.22.0.1".parse::<Ipv4Addr>().unwrap()]
        );
        let p = peers_on_port(body, 44002);
        assert_eq!(
            p.into_iter().collect::<Vec<_>>(),
            vec!["10.23.0.2".parse::<Ipv4Addr>().unwrap()]
        );
        assert!(peers_on_port(body, 44003).is_empty());
        assert!(peers_on_port("", 44001).is_empty());
        // the loopback: 0100007F is 127.0.0.1
        let lo = "header\n   0: 0100007F:ABE1 0100007F:C354 01 0 0 0 0 0 0 0 1\n";
        assert_eq!(
            peers_on_port(lo, 44001).into_iter().next(),
            Some(Ipv4Addr::LOCALHOST)
        );
    }

    #[test]
    fn nft_binary_is_found() {
        // ABE_NFT wins; otherwise PATH, then /usr/sbin/nft
        std::env::set_var("ABE_NFT", "/opt/nft");
        assert_eq!(nft_bin(), PathBuf::from("/opt/nft"));
        std::env::remove_var("ABE_NFT");
        let p = nft_bin();
        assert_eq!(p.file_name().and_then(|n| n.to_str()), Some("nft"));
    }

    #[test]
    fn client_tag_round_trips() {
        let ip: Ipv4Addr = "10.22.0.1".parse().unwrap();
        let tag = format!("{TAG_CLIENT}={ip}");
        assert_eq!(tag, "abe_client=10.22.0.1");
        // what lvchange --addtag is given is what lvs gives back
        assert!(valid_tag_value(&ip.to_string()));
        let lvs = parse_lvs(&format!(
            "  0123456789abcdef0123456789abcdef|1073741824|abe|||||thin|abe_port=44001,{tag}|active\n"
        ));
        assert_eq!(tag_value(&lvs[0].tags, TAG_CLIENT), Some("10.22.0.1"));
        assert_eq!(
            tag_value(&lvs[0].tags, TAG_CLIENT).and_then(|v| v.parse::<Ipv4Addr>().ok()),
            Some(ip)
        );
        assert!(has_tag(&lvs[0].tags, TAG_CLIENT));
    }

    #[test]
    fn reexport_summary_lists_closed_ports() {
        let mut s = ReexportSummary::default();
        assert_eq!(reexport_warning(&s), None);
        s.closed = vec!["a".into(), "b".into()];
        assert_eq!(
            reexport_warning(&s).as_deref(),
            Some("2 volume(s) exported with no client; closed until attached again")
        );
        let v: serde_json::Value = serde_json::to_value(&s).unwrap();
        assert_eq!(v["closed"], serde_json::json!(["a", "b"]));
    }

    #[test]
    fn volume_and_message_carry_the_client() {
        let m = Message::exported("0123456789abcdef0123456789abcdef", "44001");
        let v: serde_json::Value = serde_json::to_value(&m).unwrap();
        assert!(v.get("client").is_none());
        let mut m = m;
        m.client = Some("10.22.0.1".into());
        let v: serde_json::Value = serde_json::to_value(&m).unwrap();
        assert_eq!(v["client"], "10.22.0.1");
        // an old reply without the field still parses
        let old: Message = serde_json::from_str(
            r#"{"message":"","id":"x","port":"44001","traddr":"10.22.0.1","nqn":"x"}"#,
        )
        .unwrap();
        assert_eq!(old.client, None);
    }

    #[test]
    fn client_ip_is_ipv4_only() {
        let v4: SocketAddr = "10.22.0.1:51000".parse().unwrap();
        assert_eq!(
            client_ip(v4).unwrap(),
            "10.22.0.1".parse::<Ipv4Addr>().unwrap()
        );
        let mapped: SocketAddr = "[::ffff:10.22.0.1]:51000".parse().unwrap();
        assert_eq!(
            client_ip(mapped).unwrap(),
            "10.22.0.1".parse::<Ipv4Addr>().unwrap()
        );
        let v6: SocketAddr = "[fd00::1]:51000".parse().unwrap();
        let e = client_ip(v6).unwrap_err();
        assert_eq!(e.status, StatusCode::BAD_REQUEST);
        assert!(e.error.starts_with("fence needs an IPv4 client address"));
    }
}
