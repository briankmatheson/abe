use if_addrs::get_if_addrs;
use nix::libc::int16_t;
use nix::mount::{MsFlags, mount};
use nix::unistd::symlinkat;
use std::path::PathBuf;
use std::fs::{self, File, write};
use std::io::{Result, Write, Read, Error, ErrorKind};
use std::fmt::Display;
use std::path::Path;
use std::process::Command;
use std::env::var;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::str;
use uuid::Uuid;
use ipnet::Ipv4Net;
use env_logger::Env;
use log::{info, warn};
use axum::{
    extract::{Path as EP, Query},
    http::StatusCode,
    routing::get,
    Json, Router
};
use serde::{Deserialize, Serialize};
//use env_inventory;


const CONFIGFS_PATH: &str = "/sys/kernel/config";
const NVMET_PATH: &str = "/sys/kernel/config/nvmet";

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
    var("ABE_ADVERTISE").ok().filter(|s| !s.is_empty()).unwrap_or_else(bind_traddr)
}

/// HTTP listen address (ABE_LISTEN, default 0.0.0.0:80).
fn listen_addr() -> String {
    var("ABE_LISTEN").unwrap_or_else(|_| "0.0.0.0:80".to_string())
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

/// Size of the LV called `id`, if it exists.
fn lv_bytes(id: &str) -> Option<u64> {
    list_lvs().ok()?.into_iter().find(|l| l.name == id).map(|l| l.bytes)
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
}

type ApiError = (StatusCode, Json<ErrorMessage>);

#[derive(Serialize)]
struct ErrorMessage {
    error: String,
}

fn api_err<E: Display>(what: &str, e: E) -> ApiError {
    let msg = format!("{what}: {e}");
    warn!("{msg}");
    (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorMessage { error: msg }))
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
}

/// A short sequential-write run on a new volume, before it is handed out:
/// how fast this pool takes 4M writes right now.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct Perf {
    bs: String,
    seconds: f64,
    write_mib_s: f64,
    write_iops: f64,
    /// mean completion latency
    write_lat_ms: f64,
}

/// How long fio writes to each new volume (ABE_FIO_SECONDS, default 5;
/// 0 disables) and with what block size (ABE_FIO_BS, default 4M).
fn fio_seconds() -> u64 {
    var("ABE_FIO_SECONDS").ok().and_then(|s| s.parse().ok()).unwrap_or(5)
}
fn fio_bs() -> String {
    var("ABE_FIO_BS").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "4M".to_string())
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
}

/// More snapshot layers than this under one volume earns a warning.
const MAX_SNAPSHOT_LAYERS: u32 = 10;

#[derive(Deserialize, Default)]
struct CloneParams {
    /// size of the clone; defaults to the origin's, and cannot be smaller
    bytes: Option<u64>,
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
}

async fn configure(Query(p): Query<ConfigureParams>) -> std::result::Result<Json<Message>, ApiError> {
    let size = match (p.bytes, p.size) {
        (Some(b), _) => bytes_to_lv_size(b),
        (None, Some(s)) if !s.is_empty() => s,
        _ => default_vol_size(),
    };
    let id: String = Uuid::new_v4().to_string().replace("-", "");
    create_lv(&id, &size, p.raw.unwrap_or(false)).map_err(|e| api_err("create_lv", e))?;
    info!("attach id is {}", id);
    let Json(mut m) = do_attach(id.clone()).await?;
    // Measure after the export is set up so a fio problem cannot cost the
    // caller its volume; the data written is garbage on a blank volume.
    let dev = lv_path_for_uuid(&id);
    m.perf = match tokio::task::spawn_blocking(move || characterize(&dev)).await {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => { warn!("fio on {id}: {e}"); None }
        Err(e) => { warn!("fio task on {id}: {e}"); None }
    };
    Ok(Json(m))
}

/// Sequential writes with fio for ABE_FIO_SECONDS at ABE_FIO_BS, direct
/// I/O, straight at the LV. Ok(None) when disabled.
fn characterize(dev: &str) -> Result<Option<Perf>> {
    let secs = fio_seconds();
    if secs == 0 {
        return Ok(None);
    }
    let bs = fio_bs();
    info!("fio: {secs}s of {bs} sequential writes on {dev}");
    let out = Command::new("fio")
        .args(["--name=abe", "--filename", dev, "--rw=write", "--bs", &bs,
               "--direct=1", "--ioengine=libaio", "--iodepth=8",
               "--time_based", "--runtime", &secs.to_string(),
               "--output-format=json"])
        .output()?;
    check(out.clone(), "fio")?;
    let perf = parse_fio(&String::from_utf8_lossy(&out.stdout), &bs)
        .ok_or_else(|| Error::new(ErrorKind::Other, "fio printed no write results"))?;
    info!("fio on {dev}: {:.0} MiB/s, {:.0} IOPS, {:.2} ms mean latency at bs={bs}",
          perf.write_mib_s, perf.write_iops, perf.write_lat_ms);
    Ok(Some(perf))
}

/// Pull the write numbers out of `fio --output-format=json`.
fn parse_fio(json: &str, bs: &str) -> Option<Perf> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let job = v.get("jobs")?.as_array()?.first()?;
    let w = job.get("write")?;
    let runtime_ms = w.get("runtime")?.as_f64()?;
    let bw_bytes = w.get("bw_bytes")?.as_f64()?;
    let iops = w.get("iops")?.as_f64()?;
    let lat_ns = w.get("clat_ns").and_then(|c| c.get("mean")).and_then(|m| m.as_f64()).unwrap_or(0.0);
    let round = |x: f64| (x * 100.0).round() / 100.0;
    Some(Perf {
        bs: bs.to_string(),
        seconds: round(runtime_ms / 1000.0),
        write_mib_s: round(bw_bytes / (1024.0 * 1024.0)),
        write_iops: round(iops),
        write_lat_ms: round(lat_ns / 1e6),
    })
}

async fn attach(EP(id): EP<String>) -> std::result::Result<Json<Message>, ApiError> {
    info!("attach id is {}", id);
    if !Path::new(&lv_path_for_uuid(&id)).exists() {
        return Err((StatusCode::NOT_FOUND, Json(ErrorMessage { error: format!("no volume {id}") })));
    }
    do_attach(id).await
}

/// DELETE /id/<id>: stop exporting the volume and remove its LV.
/// Idempotent: returns 404 only if neither an export nor an LV exists.
async fn detach(EP(id): EP<String>) -> std::result::Result<Json<Message>, ApiError> {
    info!("delete id is {}", id);
    let lv = lv_path_for_uuid(&id);
    let exported = existing_export(&id).is_some();
    if !exported && !Path::new(&lv).exists() {
        return Err((StatusCode::NOT_FOUND, Json(ErrorMessage { error: format!("no volume {id}") })));
    }
    let port = remove_export(&id).map_err(|e| api_err("nvmet teardown", e))?;
    if Path::new(&lv).exists() {
        remove_holders(&lv).map_err(|e| api_err("remove partition mappings", e))?;
        check(Command::new("/usr/sbin/lvremove").args(["-y", &lv]).output()
                  .map_err(|e| api_err("lvremove", e))?, "lvremove")
            .map_err(|e| api_err("lvremove", e))?;
    }
    if let Some(p) = &port {
        match Command::new("/usr/sbin/ufw").args(["delete", "allow", p]).output() {
            Ok(o) => info!("ufw delete allow {p}: {}", o.status),
            Err(e) => info!("ufw not available ({e}); skipping firewall rule"),
        }
    }
    Ok(Json(Message {
        message: format!("deleted {id}"),
        nqn: id.clone(),
        id,
        port: port.unwrap_or_default(),
        traddr: advertised_traddr(),
        bytes: None,
        perf: None,
    }))
}

/// GET /volumes: every volume in the VG (exported or not).
async fn volumes() -> std::result::Result<Json<Vec<Volume>>, ApiError> {
    list_volumes().map(Json).map_err(|e| api_err("lvs", e))
}

/// GET /utilization: how full the thin pool (or VG) is.
async fn utilization() -> std::result::Result<Json<Utilization>, ApiError> {
    let lvs = list_lvs().map_err(|e| api_err("lvs", e))?;
    let (vg_bytes, vg_free) = vg_space().map_err(|e| api_err("vgs", e))?;
    summarize(&vg_name(), thin_pool().as_deref(), &lvs, vg_bytes, vg_free)
        .map(Json)
        .map_err(|e| api_err("utilization", e))
}

/// GET /clone/<id>[?bytes=N]: create a new volume that starts out as a copy
/// of <id> (a thin snapshot: it shares the origin's blocks until either side
/// writes) and export it. The origin may be any thin volume in abe's pool.
async fn clone_volume(EP(origin): EP<String>, Query(p): Query<CloneParams>)
                      -> std::result::Result<Json<CloneReply>, ApiError> {
    info!("clone of {origin}");
    let bad = |code, error: String| (code, Json(ErrorMessage { error }));
    let lvs = list_lvs().map_err(|e| api_err("lvs", e))?;
    let Some(src) = lvs.iter().find(|l| l.name == origin) else {
        return Err(bad(StatusCode::NOT_FOUND, format!("no volume {origin}")));
    };
    if src.segtype != "thin" || src.pool.is_none() || src.pool != thin_pool() {
        return Err(bad(StatusCode::BAD_REQUEST, format!(
            "{origin} is not a thin volume in abe's pool ({}/{}); only those can be cloned",
            vg_name(), thin_pool().unwrap_or_else(|| "<ABE_THIN_POOL not set>".to_string()))));
    }
    if let Some(b) = p.bytes {
        if b < src.bytes {
            return Err(bad(StatusCode::BAD_REQUEST, format!(
                "a clone cannot be smaller than its origin ({b} < {} bytes)", src.bytes)));
        }
    }
    let grow_to = p.bytes.filter(|b| *b > src.bytes);

    let id: String = Uuid::new_v4().to_string().replace("-", "");
    let layers = layers(&lvs, &origin) + 1;
    let warning = layer_warning(&id, layers);
    if let Some(w) = &warning {
        warn!("{w}");
    }
    clone_lv(&origin, &id, grow_to).map_err(|e| api_err("clone_lv", e))?;
    let bytes = list_lvs().ok()
        .and_then(|l| l.into_iter().find(|l| l.name == id).map(|l| l.bytes))
        .unwrap_or(grow_to.unwrap_or(src.bytes));
    let Json(export) = do_attach(id).await?;
    Ok(Json(CloneReply { export, bytes, origin, layers, warning }))
}

/// Thin snapshot of `origin` named `name`, activated, optionally grown to
/// `grow_to` bytes. Nothing is left behind if a step fails.
fn clone_lv(origin: &str, name: &str, grow_to: Option<u64>) -> Result<()> {
    let vg = vg_name();
    let lv = format!("{vg}/{name}");
    info!("making thin snapshot {lv} of {vg}/{origin}");
    check(Command::new("/usr/sbin/lvcreate")
              .args(["-y", "-s", "-n", name, &format!("{vg}/{origin}")]).output()?, "lvcreate -s")?;
    // Thin snapshots are created with the activation-skip flag set; clear it
    // so the volume comes up now and after every reboot.
    let finish = || -> Result<()> {
        check(Command::new("/usr/sbin/lvchange").args(["-y", "-kn", &lv]).output()?, "lvchange -kn")?;
        check(Command::new("/usr/sbin/lvchange").args(["-y", "-ay", &lv]).output()?, "lvchange -ay")?;
        if let Some(b) = grow_to {
            check(Command::new("/usr/sbin/lvextend")
                      .args(["-y", "-L", &bytes_to_lv_size(b), &lv]).output()?, "lvextend")?;
        }
        Ok(())
    };
    if let Err(e) = finish() {
        match Command::new("/usr/sbin/lvremove").args(["-y", &lv]).output() {
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

const LVS_FIELDS: &str = "lv_name,lv_size,pool_lv,origin,data_percent,metadata_percent,lv_metadata_size,segtype";

/// Every LV in the VG.
fn list_lvs() -> Result<Vec<Lv>> {
    let out = Command::new("/usr/sbin/lvs")
        .env("LC_ALL", "C")
        .args(["--noheadings", "--units", "b", "--nosuffix", "--separator", "|", "-o", LVS_FIELDS, &vg_name()])
        .output()?;
    check(out.clone(), "lvs")?;
    Ok(parse_lvs(&String::from_utf8_lossy(&out.stdout)))
}

/// Parse `lvs --noheadings --units b --nosuffix --separator '|' -o LVS_FIELDS`.
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
        });
    }
    lvs
}

/// (size, free) of the VG in bytes.
fn vg_space() -> Result<(u64, u64)> {
    let out = Command::new("/usr/sbin/vgs")
        .env("LC_ALL", "C")
        .args(["--noheadings", "--units", "b", "--nosuffix", "--separator", "|", "-o", "vg_size,vg_free", &vg_name()])
        .output()?;
    check(out.clone(), "vgs")?;
    let text = String::from_utf8_lossy(&out.stdout);
    parse_vgs(&text).ok_or_else(|| Error::new(ErrorKind::Other, format!("cannot parse vgs output {:?}", text.trim())))
}

fn parse_vgs(text: &str) -> Option<(u64, u64)> {
    let mut f = text.lines().find(|l| !l.trim().is_empty())?.split('|').map(str::trim);
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
        match lvs.iter().find(|l| l.name == cur).and_then(|l| l.origin.as_deref()) {
            Some(o) => { depth += 1; cur = o; }
            None => break,
        }
    }
    depth
}

fn layer_warning(name: &str, layers: u32) -> Option<String> {
    (layers > MAX_SNAPSHOT_LAYERS).then(|| format!(
        "{name} has {layers} snapshot layers (more than {MAX_SNAPSHOT_LAYERS})"))
}

/// `pct` percent of `bytes`. lvs reports percentages to two decimals, so
/// this is only that precise.
fn percent_of(bytes: u64, pct: f64) -> u64 {
    ((bytes as f64) * pct / 100.0).round() as u64
}

fn summarize(vg: &str, pool: Option<&str>, lvs: &[Lv], vg_bytes: u64, vg_free: u64) -> Result<Utilization> {
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
    };
    if let Some(pool) = pool {
        let p = lvs.iter().find(|l| l.name == pool && l.segtype == "thin-pool")
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("no thin pool {vg}/{pool}")))?;
        let pct = p.data_percent
            .ok_or_else(|| Error::new(ErrorKind::Other, format!("thin pool {vg}/{pool} reports no usage (inactive?)")))?;
        u.bytes = p.bytes;
        u.used_bytes = percent_of(p.bytes, pct).min(p.bytes);
        u.free_bytes = p.bytes - u.used_bytes;
        u.data_percent = pct;
        u.metadata_percent = p.metadata_percent;
        u.metadata_bytes = p.metadata_bytes;
        u.provisioned_bytes = lvs.iter()
            .filter(|l| l.segtype == "thin" && l.pool.as_deref() == Some(pool))
            .map(|l| l.bytes).sum();
    } else if u.bytes > 0 {
        u.data_percent = ((u.used_bytes as f64) * 10000.0 / (u.bytes as f64)).round() / 100.0;
    }
    Ok(u)
}

fn list_volumes() -> Result<Vec<Volume>> {
    let lvs = list_lvs()?;
    let traddr = advertised_traddr();
    let mut vols = Vec::new();
    for l in lvs.iter().filter(|l| is_volume_id(&l.name)) {
        let n = layers(&lvs, &l.name);
        vols.push(Volume {
            id: l.name.clone(),
            bytes: l.bytes,
            port: existing_export(&l.name),
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
        });
    }
    Ok(vols)
}

/// udev creates a device-mapper partition map (abe-<id>p1) for the GPT
/// partition on the LV; it holds the LV open and makes lvremove fail with
/// "used by another device". Remove any such holders.
fn remove_holders(lv: &str) -> Result<()> {
    let dm = fs::canonicalize(lv)?;
    let dm = dm.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_string();
    let holders = match fs::read_dir(format!("/sys/block/{dm}/holders")) {
        Ok(h) => h,
        Err(_) => return Ok(()),
    };
    for h in holders.flatten() {
        let name = fs::read_to_string(h.path().join("dm/name"))?.trim().to_string();
        info!("removing holder {name}");
        check(Command::new("/usr/sbin/dmsetup").args(["remove", "--retry", &name]).output()?, "dmsetup remove")?;
    }
    Ok(())
}

/// Tear down the nvmet port + subsystem for `id`. Returns the trsvcid the
/// volume was exported on, if any. Missing pieces are not errors.
fn remove_export(id: &str) -> Result<Option<String>> {
    let mut svc = None;
    if let Ok(ports) = fs::read_dir(format!("{NVMET_PATH}/ports")) {
        for p in ports.flatten() {
            let link = p.path().join("subsystems").join(id);
            if !link.exists() {
                continue;
            }
            svc = fs::read_to_string(p.path().join("addr_trsvcid")).ok().map(|s| s.trim().to_string());
            info!("unlinking {}", link.display());
            fs::remove_file(&link)?;
            // Drop the port too if nothing else is exported through it.
            let empty = fs::read_dir(p.path().join("subsystems")).map(|mut d| d.next().is_none()).unwrap_or(false);
            if empty {
                info!("removing port {}", p.path().display());
                fs::remove_dir(p.path())?;
            }
        }
    }
    let subsys = PathBuf::from(format!("{NVMET_PATH}/subsystems/{id}"));
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
    let ports = fs::read_dir(format!("{NVMET_PATH}/ports")).ok()?;
    for p in ports.flatten() {
        if p.path().join("subsystems").join(id).exists() {
            let svc = fs::read_to_string(p.path().join("addr_trsvcid")).ok()?;
            return Some(svc.trim().to_string());
        }
    }
    None
}

/// Highest numbered nvmet port directory (0 if none).
fn last_port_number() -> u32 {
    fs::read_dir(format!("{NVMET_PATH}/ports"))
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()))
                .max()
                .unwrap_or(0)
        })
        .unwrap_or(0)
}

async fn do_attach(id: String) -> std::result::Result<Json<Message>, ApiError> {
    let traddr = advertised_traddr();

    // Idempotent: re-attaching an exported volume just reports where it is.
    if let Some(svc) = existing_export(&id) {
        info!("{id} already exported on port {svc}");
        return Ok(Json(Message {
            message: format!("sudo nvme connect -a {traddr} -t tcp -s {svc} -n {id}"),
            nqn: id.clone(),
            bytes: lv_bytes(&id),
            id,
            port: svc,
            traddr,
            perf: None,
        }));
    }

    let i = last_port_number() + 1;
    info!("allocating port {i}");

    let lv_path = lv_path_for_uuid(&id);
    
    let target = Subsystem::create(&id).await.map_err(|e| api_err("nvmet subsystem", e))?;
    target.add_namespace("1", &lv_path).await.map_err(|e| api_err("nvmet namespace", e))?;

    let svc_port = format!("44{:03}", i);
    info!("svc_port is {svc_port}");
	

    let port  = Port::create(id.clone(), &svc_port, "tcp", i).map_err(|e| api_err("nvmet port", e))?;
    port.link_subsystem(&target);
	
    println!("{} {}:{}", port.id, port.traddr, port.trsvcid);
    match Command::new("/usr/sbin/ufw").args(["allow", &port.trsvcid]).output() {
        Ok(o) => info!("ufw allow {}: {}", port.trsvcid, o.status),
        Err(e) => info!("ufw not available ({}); skipping firewall rule", e),
    }
    
    Ok(Json(Message {
        message: format!("sudo nvme discover -a {} -t tcp -s {} ; sudo nvme connect -a {} -t tcp -s {} -n {}",
			 traddr,
			 port.trsvcid,
			 traddr,
			 port.trsvcid,
			 id),
        nqn: id.clone(),
        bytes: lv_bytes(&id),
        id,
        port: port.trsvcid,
        traddr,
        perf: None,
    }))
}

// NVME over TCP target subsystem
struct Subsystem {
    name: String,
}
impl Subsystem {
    async fn create(name: &str) -> Result<Self> {
        let path = format!("{}/subsystems/{}", NVMET_PATH, name);

        info!("making nvmet subsystem dir");
        fs::create_dir_all(&path)?;

        info!("allowing any host");
        fs::write(format!("{}/attr_allow_any_host", path), "1");
        Ok(Self {
            name: name.to_string(),
        })
    }
    async fn add_namespace(&self, nsid: &str, device_path: &str) -> Result<()> {
        let ns_path = format!(
            "{}/subsystems/{}/namespaces/{}",
            NVMET_PATH, self.name, nsid
        );
        info!("making namespace {ns_path}");     
        fs::create_dir_all(&ns_path);

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

// NVME over TCP port
struct Port {
    id: String,
    traddr: String,
    trsvcid: String,
    iteration: u32
}
impl Port {
    fn create(id: String, svcid: &str, trtype: &str, iteration: u32) -> Result<Port> {    
        let path = format!("{}/ports/{}", NVMET_PATH, iteration);
        info!("making port {path}");
        // nvmet-tcp accepts 0.0.0.0 to listen on every interface; override
        // with ABE_TRADDR to pin a specific one.
        let traddr: String = bind_traddr();
	let mut trsvcid: String = svcid.to_string();
        let result = fs::create_dir_all(&path);
	if result.is_ok() {
            info!("writing addr_traddr {path}");
            File::create(format!("{}/addr_traddr", path))?.write_all(traddr.as_bytes())?;
	    
            info!("writing addr_trsvcid{path}");
            File::create(format!("{}/addr_trsvcid", path))?.write_all(trsvcid.as_bytes())?;
	    
            info!("making addr_trtype {path}");
            File::create(format!("{}/addr_trtype", path))?.write_all(trtype.as_bytes())?;
	    
            info!("making addr_adrfam {path}");
            File::create(format!("{}/addr_adrfam", path))?.write_all("ipv4".as_bytes())?;
	} else {
	    // find the old stuff
	    let mut buffer: [u8; 1024] = [0; 1024];
	    File::open("{path}/addr_trsvcid")?.read(&mut buffer)?;
	    let trsvcid = str::from_utf8_mut(&mut buffer).unwrap();
	}
        Ok(Port{
	    id: id, 
	    traddr: traddr, 
	    trsvcid: trsvcid, 
	    iteration: iteration
	})
    }
    
    fn link_subsystem(&self, subsystem: &Subsystem) -> Result<()> {
        let subsys_path: String = format!("{}/subsystems/{}", NVMET_PATH, subsystem.name);
        let port_subsys_link: String = format!(
            "{}/ports/{}/subsystems/{}",
            NVMET_PATH, self.iteration, subsystem.name
        );
        info!("linking port to subsystem");
        symlinkat(subsys_path.as_str(), None, port_subsys_link.as_str())?;

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

fn lv_path_for_uuid(uuid: &str) ->  String {
    format!("/dev/{}/{uuid}", vg_name())
}

fn ensure_nvmet_present() -> Result<()> {
    info!("making nvmet subsystem");        
    if !Path::new(NVMET_PATH).exists() {
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
                .args(["-y", "-W", "y", "-V", size, "-T", &format!("{vg}/{pool}"), "-n", name])
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
    check(Command::new("/usr/sbin/parted").args(["-s", &dev, "mklabel", "gpt"]).output()?, "parted mklabel")?;
    check(Command::new("/usr/sbin/parted").args(["-s", &dev, "mkpart", "primary", "1MiB", "100%"]).output()?, "parted mkpart")?;
    check(Command::new("/usr/sbin/parted").args(["-s", &dev, "name", "1", name]).output()?, "parted name")?;
    info!("created {dev} ({size})");
    Ok(())
}

fn check(output: std::process::Output, what: &str) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
    warn!("{what} failed: {err}");
    Err(Error::new(ErrorKind::Other, format!("{what} failed: {err}")))
}    


#[tokio::main]
async fn main() {
    env_logger::init();
    
    ensure_configfs_mounted();
    ensure_nvmet_present();

    let app = Router::new()
        .route("/id/:id", get(attach).delete(detach))
        .route("/configure", get(configure))
        .route("/clone/:id", get(clone_volume))
        .route("/volumes", get(volumes))
        .route("/utilization", get(utilization));

    info!("vg={} thin_pool={:?} bind={} advertise={}", vg_name(), thin_pool(), bind_traddr(), advertised_traddr());
    let listener = tokio::net::TcpListener::bind(listen_addr()).await.unwrap();
    if let Ok(addrs) = get_if_addrs() {
        for iface in addrs {
            if iface.ip().is_ipv4() && !iface.is_loopback() {
		println!("Listening on http://{}", iface.ip());
	    }
	}
    }
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    // What `lvs --noheadings --units b --nosuffix --separator '|' -o LVS_FIELDS`
    // prints: a thick LV, a thin pool, a base image, two abe volumes (the
    // second a clone of the first) and an inactive snapshot.
    const LVS: &str = "\
  root|99996401664||||||linear
  abe|1398887514112|||12.34|10.50|2147483648|thin-pool
  base-xdebbie-base|10737418240|abe||25.00|||thin
  0123456789abcdef0123456789abcdef|42949672960|abe|base-xdebbie-base|50.00|||thin
  fedcba9876543210fedcba9876543210|42949672960|abe|0123456789abcdef0123456789abcdef|0.00|||thin
  parked|10737418240|abe|[gone]||||thin
";

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
        assert_eq!(lvs[0], Lv {
            name: "root".into(), bytes: 99996401664, pool: None, origin: None, data_percent: None,
            metadata_percent: None, metadata_bytes: None, segtype: "linear".into(),
        });
        assert_eq!(lvs[1].segtype, "thin-pool");
        assert_eq!(lvs[1].data_percent, Some(12.34));
        assert_eq!(lvs[1].metadata_percent, Some(10.5));
        assert_eq!(lvs[1].metadata_bytes, Some(2147483648));
        assert_eq!(lvs[3].pool.as_deref(), Some("abe"));
        assert_eq!(lvs[3].origin.as_deref(), Some("base-xdebbie-base"));
        assert_eq!(lvs[5].origin.as_deref(), Some("gone"));
        assert_eq!(lvs[5].data_percent, None);
    }

    #[test]
    fn skips_garbage_lines() {
        assert!(parse_lvs("").is_empty());
        assert!(parse_lvs("  WARNING: something\n\n  a|b\n  x|notanumber||||||thin\n").is_empty());
    }

    #[test]
    fn parses_vgs() {
        assert_eq!(parse_vgs("  1999307276288|599785537536\n"), Some((1999307276288, 599785537536)));
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
        assert_eq!(layer_warning("v11", layers(&lvs, "v11")).as_deref(),
                   Some("v11 has 11 snapshot layers (more than 10)"));
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
        let u = summarize("timesink-vg", Some("abe"), &lvs, 1999307276288, 599785537536).unwrap();
        assert_eq!(u.bytes, 1398887514112);
        assert_eq!(u.used_bytes, 172622719241); // 12.34 %
        assert_eq!(u.free_bytes, 1398887514112 - 172622719241);
        assert_eq!(u.data_percent, 12.34);
        assert_eq!(u.metadata_percent, Some(10.5));
        assert_eq!(u.metadata_bytes, Some(2147483648));
        // base + two volumes + parked; not root, not the pool itself
        assert_eq!(u.provisioned_bytes, 10737418240 + 2 * 42949672960 + 10737418240);
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
        assert_eq!((u.bytes, u.used_bytes, u.free_bytes), (4 << 30, 1 << 30, 3 << 30));
        assert_eq!(u.data_percent, 25.0);
        assert_eq!(u.metadata_percent, None);
        assert_eq!(u.volumes, 1);
    }

    #[test]
    fn summary_lists_deep_chains() {
        let mut lvs = chain(12);
        lvs.push(Lv { name: "abe".into(), segtype: "thin-pool".into(), pool: None, ..thin("abe", None) });
        let u = summarize("abe", Some("abe"), &lvs, 1 << 40, 0).unwrap();
        assert_eq!(u.max_layers, 12);
        assert_eq!(u.warnings, vec![
            "v11 has 11 snapshot layers (more than 10)".to_string(),
            "v12 has 12 snapshot layers (more than 10)".to_string(),
        ]);
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
            "io_bytes": 6442450944, "bw_bytes": 1287350000, "bw": 1257177, "iops": 306.94,
            "runtime": 5004, "clat_ns": {"min": 1000, "max": 90000000, "mean": 26012345.6}}}]}"#;
        let p = parse_fio(json, "4M").unwrap();
        assert_eq!(p.bs, "4M");
        assert_eq!(p.seconds, 5.0);
        assert_eq!(p.write_mib_s, 1227.71);
        assert_eq!(p.write_iops, 306.94);
        assert_eq!(p.write_lat_ms, 26.01);
    }

    #[test]
    fn fio_without_results_is_none() {
        assert_eq!(parse_fio("", "4M"), None);
        assert_eq!(parse_fio(r#"{"jobs": []}"#, "4M"), None);
        assert_eq!(parse_fio(r#"{"jobs": [{"read": {"bw_bytes": 1}}]}"#, "4M"), None);
    }

    #[test]
    fn recognises_volume_ids() {
        assert!(is_volume_id("0123456789abcdef0123456789abcdef"));
        assert!(!is_volume_id("base-xdebbie-base"));
        assert!(!is_volume_id("0123456789abcdef0123456789abcde"));
        assert!(!is_volume_id("0123456789abcdef0123456789abcdeg"));
    }
}
