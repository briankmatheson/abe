//! IOPS arbiter: shares the drive between the exported volumes.
//!
//! Every volume abe exports sits on the same drive as whatever else the host
//! runs (on an xdebbie hub: the VMs' own disks, etcd among them). Left alone,
//! one busy volume can take the whole drive. abe sees every volume's live
//! load, so it decides how much each may have; the initiators enforce it
//! (abe-csi writes cgroup `io.max` from `GET /qos/<id>`).
//!
//! Policy, with C the drive's IOPS (`ABE_IOPS_CAPACITY`), every
//! `ABE_QOS_INTERVAL_SECS` (5):
//!
//! - **guarantee** g, the same for every active volume: half its fair share
//!   of the ceiling, and never so much that the guarantees together pass
//!   `ABE_QOS_GUARANTEE_PCT` (33) of C: `g = min(T / n / 2, C * 33% / n)`,
//!   n the active volumes, T the total below.
//! - **per-volume ceiling** at most `ABE_QOS_CEILING_PCT` (80) of C, so one
//!   volume can burst to most of the drive while the others are quiet.
//! - **total**: the volumes together get at most T = 80% of C. While their
//!   demand is under 90% of T nothing is shaped (every ceiling is the
//!   per-volume maximum); past that the ceilings are water-filled: each
//!   active volume gets g, then the rest of T goes out max-min fair by
//!   demand, never above the per-volume maximum. An idle volume keeps g, so
//!   it can start at once; it gets more as soon as it shows demand.
//!
//! Demand is read from the kernel's per-device counters
//! (`/sys/block/dm-N/stat`, reads + writes completed) of each exported LV.
//! A volume is active when it did any I/O in the last `ACTIVE_WINDOW`
//! samples.
//!
//! The drive's capacity C: `ABE_IOPS_CAPACITY`, else what abe measured on
//! its first run and recorded (`ABE_QOS_RECORD`, /var/lib/abe/drive.json):
//! fio on a scratch LV, 4k random writes at iodepth 32 from 4 jobs, for 10 s,
//! and only while the drive is quiet (it retries every 10 min). Delete
//! the record to measure again; `ABE_QOS_MEASURE=0` never measures. Until C
//! is known nothing is shaped.

use log::{info, warn};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::env::var;
use std::fs;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

/// Samples a volume must have been idle for to stop counting as active.
const ACTIVE_WINDOW: usize = 12;
/// Below this much of the total, demand is not shaped at all.
const UNCONTENDED: f64 = 0.9;
/// A busy volume's ceiling is its demand plus this much headroom, so a
/// volume that is growing is not pinned to what it did last interval.
const HEADROOM: f64 = 1.25;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Params {
    pub capacity: f64,
    pub guarantee_pct: f64,
    pub ceiling_pct: f64,
}

fn env_num(k: &str) -> Option<f64> {
    var(k)
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .filter(|v| *v > 0.0)
}

impl Params {
    /// ABE_IOPS_CAPACITY alone (the arbiter itself also tries the record,
    /// then measures: `capacity`).
    #[cfg(test)]
    pub fn from_env() -> Option<Self> {
        env_num("ABE_IOPS_CAPACITY").map(Self::with_capacity)
    }
    pub fn with_capacity(capacity: f64) -> Self {
        Self {
            capacity,
            guarantee_pct: env_num("ABE_QOS_GUARANTEE_PCT").unwrap_or(33.0).min(100.0),
            ceiling_pct: env_num("ABE_QOS_CEILING_PCT").unwrap_or(80.0).min(100.0),
        }
    }
    fn total(&self) -> f64 {
        self.capacity * self.ceiling_pct / 100.0
    }
    fn per_volume_max(&self) -> f64 {
        self.total()
    }
}

/// One volume's share, as `/qos` reports it.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Alloc {
    /// the most this volume may do now (read + write IOPS)
    pub ceiling_iops: u64,
    /// what it gets however busy the others are
    pub guarantee_iops: u64,
    /// what it did over the last interval
    pub demand_iops: u64,
    pub active: bool,
}

/// The ceilings for this interval. `demand` holds every exported volume's
/// IOPS over the last interval; `active` those that did any I/O recently.
pub fn allocate(
    p: &Params,
    demand: &BTreeMap<String, f64>,
    active: &BTreeSet<String>,
) -> BTreeMap<String, Alloc> {
    let n = active.len().max(1) as f64;
    let total = p.total();
    let vmax = p.per_volume_max();
    let g = (total / n / 2.0).min(p.capacity * p.guarantee_pct / 100.0 / n);
    let busy: f64 = demand
        .iter()
        .filter(|(id, _)| active.contains(*id))
        .map(|(_, d)| *d)
        .sum();

    let mut ceiling: BTreeMap<String, f64> = BTreeMap::new();
    if busy <= total * UNCONTENDED {
        for id in demand.keys() {
            ceiling.insert(id.clone(), vmax);
        }
    } else {
        // Everyone starts at the guarantee; the rest of the total goes to
        // the active volumes, max-min fair by what they want.
        let mut want: Vec<(String, f64)> = demand
            .iter()
            .filter(|(id, _)| active.contains(*id))
            .map(|(id, d)| (id.clone(), (d * HEADROOM).clamp(g, vmax) - g))
            .collect();
        want.sort_by(|a, b| a.1.total_cmp(&b.1));
        let mut rest = (total - g * want.len() as f64).max(0.0);
        let mut left = want.len();
        for (id, w) in want {
            let share = rest / left as f64;
            let give = w.min(share);
            ceiling.insert(id, g + give);
            rest -= give;
            left -= 1;
        }
        for id in demand.keys() {
            ceiling.entry(id.clone()).or_insert(g);
        }
    }
    demand
        .iter()
        .map(|(id, d)| {
            (
                id.clone(),
                Alloc {
                    ceiling_iops: ceiling[id].max(g).round() as u64,
                    guarantee_iops: g.round() as u64,
                    demand_iops: d.round() as u64,
                    active: active.contains(id),
                },
            )
        })
        .collect()
}

// ---------- sampling ----------

struct Sampler {
    last: BTreeMap<String, (u64, Instant)>,
    recent: BTreeMap<String, VecDeque<bool>>,
}

/// Reads + writes completed so far on the device behind `lv` (an LV path).
fn ios_completed(lv: &str) -> Option<u64> {
    let dev = fs::canonicalize(lv).ok()?;
    let name = dev.file_name()?.to_str()?.to_string();
    let stat = fs::read_to_string(format!("/sys/block/{name}/stat")).ok()?;
    let f: Vec<u64> = stat
        .split_whitespace()
        .filter_map(|x| x.parse().ok())
        .collect();
    Some(f.first()? + f.get(4)?)
}

/// The exported volumes and their backing devices, from nvmet's configfs:
/// subsystem name == volume id, namespace 1's device_path == the LV.
fn exported(nvmet: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Ok(rd) = fs::read_dir(format!("{nvmet}/subsystems")) else {
        return out;
    };
    for e in rd.flatten() {
        let id = e.file_name().to_string_lossy().to_string();
        let ns = e.path().join("namespaces");
        let Ok(nss) = fs::read_dir(&ns) else { continue };
        for n in nss.flatten() {
            if let Ok(p) = fs::read_to_string(n.path().join("device_path")) {
                let p = p.trim().to_string();
                if !p.is_empty() && Path::new(&p).exists() {
                    out.insert(id.clone(), p);
                    break;
                }
            }
        }
    }
    out
}

impl Sampler {
    fn tick(
        &mut self,
        devices: &BTreeMap<String, String>,
    ) -> (BTreeMap<String, f64>, BTreeSet<String>) {
        let now = Instant::now();
        let mut demand = BTreeMap::new();
        let mut active = BTreeSet::new();
        for (id, lv) in devices {
            let Some(c) = ios_completed(lv) else { continue };
            let iops = match self.last.get(id) {
                Some((c0, t0)) if c >= *c0 => {
                    let dt = now.duration_since(*t0).as_secs_f64();
                    if dt > 0.0 {
                        (c - c0) as f64 / dt
                    } else {
                        0.0
                    }
                }
                _ => 0.0,
            };
            self.last.insert(id.clone(), (c, now));
            let r = self.recent.entry(id.clone()).or_default();
            r.push_back(iops >= 1.0);
            while r.len() > ACTIVE_WINDOW {
                r.pop_front();
            }
            if r.iter().any(|b| *b) {
                active.insert(id.clone());
            }
            demand.insert(id.clone(), iops);
        }
        self.last.retain(|id, _| devices.contains_key(id));
        self.recent.retain(|id, _| devices.contains_key(id));
        (demand, active)
    }
}

// ---------- shared state and the task ----------

#[derive(Serialize, Clone, Default)]
pub struct Report {
    /// false: no capacity known (yet), nothing is shaped
    pub enabled: bool,
    pub capacity_iops: u64,
    /// where capacity_iops came from: "ABE_IOPS_CAPACITY", "measured <when>"
    pub capacity_source: String,
    pub total_ceiling_iops: u64,
    pub contended: bool,
    pub volumes: BTreeMap<String, Alloc>,
}

fn state() -> &'static Mutex<Report> {
    static S: OnceLock<Mutex<Report>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(Report::default()))
}

pub fn report() -> Report {
    state().lock().unwrap().clone()
}

// ---------- the drive's capacity ----------

/// Where the first-run measurement is kept (ABE_QOS_RECORD).
fn record_path() -> String {
    var("ABE_QOS_RECORD")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/var/lib/abe/drive.json".into())
}

#[derive(Serialize, serde::Deserialize)]
struct Record {
    capacity_iops: f64,
    measured_at: String,
    how: String,
}

fn load_record() -> Option<Record> {
    serde_json::from_str(&fs::read_to_string(record_path()).ok()?).ok()
}

fn save_record(iops: f64) -> std::io::Result<Record> {
    let r = Record {
        capacity_iops: iops.round(),
        measured_at: chrono::Utc::now().to_rfc3339(),
        how: "fio: 4k random writes, iodepth 32, 4 jobs, direct, on a scratch LV".into(),
    };
    let p = record_path();
    if let Some(d) = Path::new(&p).parent() {
        fs::create_dir_all(d)?;
    }
    fs::write(&p, serde_json::to_vec_pretty(&r)?)?;
    Ok(r)
}

/// The drive's IOPS: ABE_IOPS_CAPACITY, else the recorded first-run
/// measurement, else measure now (once, then recorded) unless
/// ABE_QOS_MEASURE=0. Delete the record to measure again.
async fn capacity(measure: fn() -> std::io::Result<f64>) -> Option<(f64, String)> {
    if let Some(c) = env_num("ABE_IOPS_CAPACITY") {
        return Some((c, "ABE_IOPS_CAPACITY".into()));
    }
    if let Some(r) = load_record() {
        return Some((r.capacity_iops, format!("measured {}", r.measured_at)));
    }
    if var("ABE_QOS_MEASURE").is_ok_and(|v| v == "0") {
        info!("qos: no ABE_IOPS_CAPACITY, no record and ABE_QOS_MEASURE=0: exports are not shaped");
        return None;
    }
    // Measure, on a quiet drive: measure_drive refuses while the drive is
    // busy; try again every ABE_QOS_RETRY_SECS (600) until it works.
    let retry = var("ABE_QOS_RETRY_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(600);
    loop {
        match tokio::task::spawn_blocking(measure).await {
            Ok(Ok(iops)) if iops > 0.0 => {
                return match save_record(iops) {
                    Ok(r) => {
                        info!("qos: the drive does {:.0} IOPS; recorded in {}", iops, record_path());
                        Some((r.capacity_iops, format!("measured {}", r.measured_at)))
                    }
                    Err(e) => {
                        warn!("qos: measured {iops:.0} IOPS but could not record it in {}: {e}", record_path());
                        Some((iops, "measured (not recorded)".into()))
                    }
                };
            }
            Ok(Ok(_)) => warn!("qos: the measurement came back empty"),
            Ok(Err(e)) => warn!("qos: not measuring the drive yet: {e}; again in {retry}s (or set ABE_IOPS_CAPACITY)"),
            Err(e) => warn!("qos: measurement task: {e}"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(retry)).await;
    }
}

/// Start the arbiter: find the drive's capacity (measuring it on the first
/// run), then shape every interval. Not shaping meanwhile, or at all if no
/// capacity can be had.
pub fn spawn(nvmet: String, measure: fn() -> std::io::Result<f64>) {
    tokio::spawn(async move {
        let Some((cap, source)) = capacity(measure).await else {
            return;
        };
        run(nvmet, Params::with_capacity(cap), source).await;
    });
}

async fn run(nvmet: String, p: Params, source: String) {
    let secs = var("ABE_QOS_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(5);
    info!(
        "qos: {} IOPS drive ({source}); volumes together at most {}%, each at most {}%, guarantees together at most {}%; every {secs}s",
        p.capacity, p.ceiling_pct, p.ceiling_pct, p.guarantee_pct
    );
    {
        let mut s = Sampler {
            last: BTreeMap::new(),
            recent: BTreeMap::new(),
        };
        let mut was_contended = false;
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(secs));
        loop {
            tick.tick().await;
            let nv = nvmet.clone();
            let devices = match tokio::task::spawn_blocking(move || exported(&nv)).await {
                Ok(d) => d,
                Err(e) => {
                    warn!("qos: reading exports: {e}");
                    continue;
                }
            };
            let (demand, active) = s.tick(&devices);
            let volumes = allocate(&p, &demand, &active);
            let busy: f64 = demand
                .iter()
                .filter(|(i, _)| active.contains(*i))
                .map(|(_, d)| d)
                .sum();
            let contended = busy > p.total() * UNCONTENDED;
            if contended != was_contended {
                info!(
                    "qos: {} ({:.0} IOPS across {} active volume(s), total ceiling {:.0})",
                    if contended { "shaping" } else { "not shaping" },
                    busy,
                    active.len(),
                    p.total()
                );
                was_contended = contended;
            }
            *state().lock().unwrap() = Report {
                enabled: true,
                capacity_iops: p.capacity.round() as u64,
                capacity_source: source.clone(),
                total_ceiling_iops: p.total().round() as u64,
                contended,
                volumes,
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p() -> Params {
        Params {
            capacity: 32000.0,
            guarantee_pct: 33.0,
            ceiling_pct: 80.0,
        }
    }
    fn vols(d: &[(&str, f64)]) -> (BTreeMap<String, f64>, BTreeSet<String>) {
        let demand: BTreeMap<String, f64> = d.iter().map(|(k, v)| (k.to_string(), *v)).collect();
        let active = d
            .iter()
            .filter(|(_, v)| *v > 0.0)
            .map(|(k, _)| k.to_string())
            .collect();
        (demand, active)
    }

    #[test]
    fn quiet_drive_is_not_shaped() {
        let (d, a) = vols(&[("a", 500.0), ("b", 300.0), ("c", 0.0)]);
        let r = allocate(&p(), &d, &a);
        assert!(r.values().all(|x| x.ceiling_iops == 25600), "{r:?}");
    }

    #[test]
    fn guarantee_is_half_the_fair_share_or_the_33_percent_split() {
        // 30 active: fair 25600/30 = 853, half 427; 33% of 32000 / 30 = 352.
        let d: Vec<(String, f64)> = (0..30).map(|i| (format!("v{i}"), 10.0)).collect();
        let d: Vec<(&str, f64)> = d.iter().map(|(k, v)| (k.as_str(), *v)).collect();
        let (dm, a) = vols(&d);
        let r = allocate(&p(), &dm, &a);
        assert_eq!(r["v0"].guarantee_iops, 352);
        // few active: 2 → fair 12800, half 6400; 33% split 5280.
        let (dm, a) = vols(&[("a", 1.0), ("b", 1.0)]);
        assert_eq!(allocate(&p(), &dm, &a)["a"].guarantee_iops, 5280);
    }

    #[test]
    fn contended_drive_stays_under_the_total_and_keeps_guarantees() {
        // three volumes want far more than the drive has; one is light.
        let (d, a) = vols(&[("a", 30000.0), ("b", 30000.0), ("c", 30000.0), ("d", 100.0)]);
        let r = allocate(&p(), &d, &a);
        let g = r["a"].guarantee_iops;
        let sum: u64 = r.values().map(|x| x.ceiling_iops).sum();
        assert!(sum <= 25600 + 4, "sum {sum} {r:?}");
        assert!(r.values().all(|x| x.ceiling_iops >= g));
        // the light one wants less than its guarantee, so it gets the guarantee
        assert_eq!(r["d"].ceiling_iops, g);
        // the heavy ones split the rest evenly
        assert!(r["a"].ceiling_iops.abs_diff(r["b"].ceiling_iops) <= 1);
        assert!(r.values().all(|x| x.ceiling_iops <= 25600));
    }

    #[test]
    fn an_idle_volume_keeps_its_guarantee_under_contention() {
        let (d, a) = vols(&[("a", 40000.0), ("b", 0.0)]);
        let r = allocate(&p(), &d, &a);
        assert_eq!(r["b"].ceiling_iops, r["b"].guarantee_iops);
        assert!(!r["b"].active);
        assert_eq!(r["a"].ceiling_iops, 25600);
    }

    #[test]
    fn off_without_capacity() {
        std::env::remove_var("ABE_IOPS_CAPACITY");
        assert!(Params::from_env().is_none());
    }
}
