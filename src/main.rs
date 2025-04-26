use nix::mount::{MsFlags, mount};
use nix::unistd::symlinkat;
use std::fs::{self, File};
use std::io::{Result, Write};
use std::path::Path;

const CONFIGFS_PATH: &str = "/sys/kernel/config";
const NVMET_PATH: &str = "/sys/kernel/config/nvmet";

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

    fn add_namespace(&self, nsid: u32, device_path: &str) -> Result<()> {
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
    id: u32,
}

impl Port {
    fn create(id: u32, traddr: &str, trsvcid: &str, trtype: &str) -> Result<Self> {
        let path = format!("{}/ports/{}", NVMET_PATH, id);
        fs::create_dir_all(&path)?;

        let addr_path = format!("{}/addr", path);
        fs::create_dir_all(&addr_path)?;
        File::create(format!("{}/traddr", addr_path))?.write_all(traddr.as_bytes())?;
        File::create(format!("{}/trsvcid", addr_path))?.write_all(trsvcid.as_bytes())?;
        File::create(format!("{}/trtype", addr_path))?.write_all(trtype.as_bytes())?;

        Ok(Self { id })
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

fn main() -> Result<()> {
    ensure_configfs_mounted()?;

    let subsystem = Subsystem::create("mynvme")?;
    subsystem.add_namespace(1, "/dev/nvme1n1")?;

    let port = Port::create(1, "192.168.1.100", "4420", "tcp")?;
    port.link_subsystem(&subsystem)?;

    println!("NVMe target configured with Rust!");
    Ok(())
}
