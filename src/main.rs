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
    routing::{get, post},
    Json, Router
};
use serde::{Deserialize, Serialize};
//use env_inventory;


const CONFIGFS_PATH: &str = "/sys/kernel/config";
const NVMET_PATH: &str = "/sys/kernel/config/nvmet";
/// Default LV size when /configure is called without ?size=. Override with
/// ABE_VOL_SIZE. Accepts anything lvcreate -L does (e.g. "10G", "512M").
fn default_vol_size() -> String {
    var("ABE_VOL_SIZE").unwrap_or_else(|_| "10G".to_string())
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
}

async fn configure(Query(p): Query<ConfigureParams>) -> std::result::Result<Json<Message>, ApiError> {
    let size = match (p.bytes, p.size) {
        (Some(b), _) => bytes_to_lv_size(b),
        (None, Some(s)) if !s.is_empty() => s,
        _ => default_vol_size(),
    };
    let id: String = Uuid::new_v4().to_string().replace("-", "");
    create_lv(&id, &size).map_err(|e| api_err("create_lv", e))?;
    info!("attach id is {}", id);
    do_attach(id).await
}

async fn attach(EP(id): EP<String>) -> std::result::Result<Json<Message>, ApiError> {
    info!("attach id is {}", id);
    if !Path::new(&lv_path_for_uuid(&id)).exists() {
        return Err((StatusCode::NOT_FOUND, Json(ErrorMessage { error: format!("no volume {id}") })));
    }
    do_attach(id).await
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
    let traddr = var("ABE_TRADDR").unwrap_or_else(|_| "0.0.0.0".to_string());

    // Idempotent: re-attaching an exported volume just reports where it is.
    if let Some(svc) = existing_export(&id) {
        info!("{id} already exported on port {svc}");
        return Ok(Json(Message {
            message: format!("sudo nvme connect -a {traddr} -t tcp -s {svc} -n {id}"),
            id,
            port: svc,
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
			 port.traddr,
			 port.trsvcid,
			 port.traddr,
			 port.trsvcid,
			 id),
        
        id: id,
        port: port.trsvcid,
        
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
        let traddr: String = std::env::var("ABE_TRADDR").unwrap_or_else(|_| "0.0.0.0".to_string());
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
    let s: String = format!("/dev/abe/{uuid}");
    s
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

pub fn create_lv(name: &str, size: &str) -> Result<()> {
    info!("making lv {name}");
    let output = Command::new("/usr/sbin/lvcreate")
        .args(["-y", "-W", "y", "-L", size, "-n", name, "abe"])
        .output()?;

    check(output, "lvcreate")?;
    let dev = format!("/dev/abe/{name}");
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
        .route("/id/:id", get(attach))
        .route("/configure", get(configure));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:80").await.unwrap();
    if let Ok(addrs) = get_if_addrs() {
        for iface in addrs {
            if iface.ip().is_ipv4() && !iface.is_loopback() {
		println!("Listening on http://{}", iface.ip());
	    }
	}
    }
    axum::serve(listener, app).await.unwrap();
}
