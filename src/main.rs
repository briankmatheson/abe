use nix::mount::{MsFlags, mount};
use nix::unistd::symlinkat;
use std::path::PathBuf;
use std::fs::{self, File};
use std::io::{Result, Write, Error, ErrorKind};
use std::path::Path;
use std::process::Command;
use std::env::var;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use uuid::Uuid;
use ipnet::Ipv4Net;
use env_logger::Env;
use log::{info, warn};
use axum::{
    routing::{get, post},
    Json, Router
};
use serde::{Deserialize, Serialize};
//use env_inventory;


const CONFIGFS_PATH: &str = "/sys/kernel/config";
const NVMET_PATH: &str = "/sys/kernel/config/nvmet";
const PREFIX: &str = "172.23.23.0/24";

//env_inventory::register!(RUST_LOG = "info")

#[derive(Serialize, Deserialize)]
struct Message {
    message: String,
}

async fn hello() -> Json<Message> {
    Json(Message {
        message: "Hello, world!".to_string(),
    })
}

async fn echo(Json(payload): Json<Message>) -> Json<Message> {
    Json(Message {
        message: format!("Echo: {}", payload.message),
    })
}


// NVME over TCP target subsystem
struct Subsystem {
    name: String,
}
impl Subsystem {
    async fn create(name: &str) -> Result<Self> {
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
    let output = Command::new("lvcreate")
        .args(["-y", "-W", "y", "-L", size, "-n", name, "abe"])
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
    let output = Command::new("parted")
        .args([&format!("/dev/abe/{name}"), "mklabel", "gpt"])
        .output()?;
    let output = Command::new("parted")
        .args([&format!("/dev/abe/{name}"), "mkpart", "primary", "0%", "100%"])
        .output()?;
    let output = Command::new("parted")
        .args([&format!("/dev/abe/{name}"), "name", "1", name])
        .output()?;
    let output = Command::new("mkfs.ext4")
        .args([&format!("/dev/disk/by-partlabel/{name}")])
        .output()?;
    
    Ok(())
}    

async fn configure() -> Json<Message> {
    let numpaths = fs::read_dir(format!("{NVMET_PATH}/ports")).unwrap().count();
    info!("numpaths is {}", numpaths);

    let mut last_port: &str = "0";
    let latest_entry: PathBuf;
    if numpaths > 0 {
        let first: fs::DirEntry =
            fs::read_dir(format!("{NVMET_PATH}/ports")).unwrap().nth(0).unwrap().unwrap();
        latest_entry = first.path();
        last_port = latest_entry.file_name().unwrap().to_str().unwrap();
    }
    info!("last_port is {}", last_port);

    let i = last_port.parse::<u32>().unwrap() + 1;
    info!("i is {}", i);
    
    let uuid: String = Uuid::new_v4().to_string().replace("-", "");
    create_lv(&uuid, "1G").unwrap();

    let lv_path = lv_path_for_uuid(&uuid);
    
    let target = Subsystem::create(&uuid).await.unwrap();
    target.add_namespace("1", &lv_path).unwrap();
    
    let svc_port = format!("44{:03}", i);
    info!("svc_port is {svc_port}");


    let port = Port::create(uuid.clone(), &svc_port, "tcp", i).unwrap();
    port.link_subsystem(&target);

    println!("{} {}:{}", port.id, port.traddr, port.trsvcid);
    let output = Command::new("ufw")
        .args(["allow", &port.trsvcid])
        .output().unwrap();
    info!("{:?}", output);
        
    Json(Message {
        message: format!("sudo nvme discover -a {} -t tcp -s {}; sudo nvme connect -a {} -t tcp -s {} -n {}",
			 port.traddr,
			 port.trsvcid,
			 port.traddr,
			 port.trsvcid,
			 uuid),
    })
}

#[tokio::main]
async fn main() {
    env_logger::init();
    
    ensure_configfs_mounted();
    ensure_nvmet_present();

    let app = Router::new()
        .route("/", get(hello))
        .route("/echo", post(echo))
        .route("/configure", get(configure));

    let addr = SocketAddr::from(([192, 168, 1, 24], 80));
    println!("Listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind("192.168.1.24:80").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
