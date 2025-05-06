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

const CONFIGFS_PATH: &str = "/sys/kernel/config";
const NVMET_PATH: &str = "/sys/kernel/config/nvmet";
const PREFIX: &str = "172.23.23.0/24";


struct Subsystem {
    name: String,
}

impl Subsystem {
    fn create(name: &str) -> Result<Self> {
        let path = format!("{}/subsystems/{}", NVMET_PATH, name);
        fs::create_dir_all(&path)?;
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
        fs::create_dir_all(&ns_path)?;
        File::create(format!("{}/device_path", ns_path))?.write_all(device_path.as_bytes())?;
        File::create(format!("{}/enable", ns_path))?.write_all(b"1")?;
        Ok(())
    }
}

struct Port {
    id: String,
    traddr: String
}

impl Port {
    fn create(id: String, trsvcid: &str, trtype: &str, iteration: u32) -> Result<Port> {
        let path = format!("{}/ports/{}", NVMET_PATH, id);
        fs::create_dir_all(&path)?;

        let addr_path = format!("{}/addr", path);
        fs::create_dir_all(&addr_path)?;
        let traddr: String = (PREFIX.parse::<ipnet::Ipv4Net>().unwrap().network()).to_string() + ":" + trsvcid;

        
        
        File::create(format!("{}/traddr", addr_path))?.write_all(traddr.as_bytes())?;
        File::create(format!("{}/trsvcid", addr_path))?.write_all(trsvcid.as_bytes())?;
        File::create(format!("{}/trtype", addr_path))?.write_all(trtype.as_bytes())?;
        Ok(Port{id: id, traddr: traddr })
    }

    fn link_subsystem(&self, subsystem: &Subsystem) -> Result<()> {
        let subsys_path: String = format!("{}/subsystems/{}", NVMET_PATH, subsystem.name);
        let port_subsys_link: String = format!(
            "{}/ports/{}/subsystems/{}",
            NVMET_PATH, self.id, subsystem.name
        );
        symlinkat(subsys_path.as_str(), None, port_subsys_link.as_str())?;

        Ok(())
    }

}

fn ensure_configfs_mounted() -> Result<()> {
    if !Path::new(NVMET_PATH).exists() {

        println!("Mounting configfs...");
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
    if !Path::new(NVMET_PATH).exists() {
        println!("Installing nvmet...");
        Command::new("modprobe")
            .args(["nvmet"])
            .output()
            .expect("modprobe failed");
    }
    Ok(())
}   

pub fn create_lv(name: &str, size: &str) -> Result<String> {
    let output = Command::new("lvcreate")
        .args(["-L", size, "-n", name, "extradisk"])
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

fn main() -> Result<()> {
    ensure_configfs_mounted()?;
    ensure_nvmet_present()?;

    let i = 1;
    let uuid = Uuid::new_v4().to_string();
    let subsystem = Subsystem::create(&uuid)?;
    subsystem.add_namespace(&uuid, &create_lv(&uuid, "1G")?)?;

    let port = Port::create(uuid, "4420", "tcp", i)?;
    port.link_subsystem(&subsystem)?;

    println!("{} {}", port.id, port.traddr);
    Ok(())
}
