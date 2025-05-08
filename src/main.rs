use nix::mount::{MsFlags, mount};
use nix::unistd::symlinkat;
use std::fs::{self, File};
use std::io::{Result, Write, Error, ErrorKind};
use std::path::Path;
use std::process::Command;
use std::env::var;
use std::net::Ipv4Addr;
use uuid::Uuid;
use ipnet::Ipv4Net;
use env_logger::Env;
use log::{info, warn};
use axum::{
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;



const CONFIGFS_PATH: &str = "/sys/kernel/config";
const NVMET_PATH: &str = "/sys/kernel/config/nvmet";
const PREFIX: &str = "172.23.23.0/24";


#[derive(Serialize, Deserialize)]
struct Message {
    message: String,
}

// NVME over TCP target subsystem
struct Subsystem {
    name: String,
}
impl Subsystem {
    fn create(name: &str) -> Result<Self> {
        let path = format!("{}/subsystems/{}", NVMET_PATH, name);

        info!("making nvmet subsystem dif");
        fs::create_dir_all(&path)?;

        info!("allowing any host");
        File::create(format!("{}/attr_allow_any_host", path))?.write_all(b"1")?;
        Ok(Self {
            name: name.to_string(),
        })
    }
    fn add_namespace(&self, nsid: &str, device_path: &str) -> Result<()> {
        let ns_path = format!(
            "{}/subsystems/{}/namespaces/{}",
            NVMET_PATH, self.name, nsid
        );
        info!("making namespace {ns_path}");     
        fs::create_dir_all(&ns_path)?;

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
    fn create(id: String, trsvcid: &str, trtype: &str, iteration: u32) -> Result<Port> {    
        let path = format!("{}/ports/{}", NVMET_PATH, iteration);

        info!("making port {path}");
        fs::create_dir_all(&path)?;
        let traddr: String = "192.168.1.24".to_string();
        
        info!("writing addr_traddr {path}");
        File::create(format!("{}/addr_traddr", path))?.write_all(traddr.as_bytes())?;

        info!("writing addr_trsvcid{path}");
        File::create(format!("{}/addr_trsvcid", path))?.write_all(trsvcid.as_bytes())?;

        info!("making addr_trtype {path}");
        File::create(format!("{}/addr_trtype", path))?.write_all(trtype.as_bytes())?;

        info!("making addr_adrfam {path}");
        File::create(format!("{}/addr_adrfam", path))?.write_all("ipv4".as_bytes())?;
        Ok(Port{
            id: id, 
            traddr: traddr, 
            trsvcid: trsvcid.to_string(), 
            iteration: iteration})
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

fn ensure_dummy0_present() -> Result<()> {

    Ok(())
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

pub fn create_lv(name: &str, size: &str) -> Result<String> {
    info!("making lv {name}");
    let output = Command::new("lvcreate")
        .args(["-L", size, "-n", name, "abe"])
        .output()?;

    if !output.status.success() {
        return Err(Error::new(
            ErrorKind::Other,
            format!(
                "lvcreate failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ),
        ));
    }

    Ok(format!("/dev/abe/{}", name))
}

fn configure() -> Result<()> {
    let mut paths = fs::read_dir(format!("{NVMET_PATH}/ports")).unwrap();
    let latest = paths.nth(0).unwrap().unwrap().path();
    let last_port = latest.to_string_lossy().split("/").last().unwrap().to_string();
    info!("last_port is {}", last_port);

    let i = last_port.parse::<u32>().unwrap() + 1;
    info!("i is {}", i);
    let target = Path::new(NVMET_PATH).join("ports").join(format!("{i}"));
    let uuid = Uuid::new_v4().to_string();

    let lv_path = create_lv(&uuid, "1G")?;
    
    let target = Subsystem::create(&uuid)?;
    target.add_namespace("1", &lv_path)?;
    let svc_port = format!("44{:03}", i);
    info!("svc_port is {svc_port}");


    let port = Port::create(uuid, &svc_port, "tcp", i)?;
    port.link_subsystem(&target)?;

    println!("{} {}:{}", port.id, port.traddr, port.trsvcid);
    Ok(())
}

fn main() -> Result<()> {
    env_logger::init();
    
    ensure_configfs_mounted()?;
    ensure_nvmet_present()?;
    
    configure();
    Ok(())
}
