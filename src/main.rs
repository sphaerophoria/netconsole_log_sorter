extern crate arp;
extern crate hwaddr;
#[macro_use] extern crate error_chain;
extern crate linear_map;
extern crate arraydeque;

use std::io::Write;
use std::net::{IpAddr, UdpSocket};
use std::fs::{OpenOptions, File};
use std::path::{PathBuf};
use std::os::unix::fs::MetadataExt;
use std::ffi::OsStr;
use std::convert::From;
use std::env;
use arraydeque::ArrayDeque;
use hwaddr::HwAddr;
use linear_map::LinearMap;

error_chain!{}

fn get_mac_from_ip(ip: &IpAddr) -> Result<HwAddr> {
    let arp_table = arp::get_arp_table()
        .chain_err(|| "Failed to get arp table")?;

    arp_table
        .iter()
        .find(|item| item.ip == *ip)
        .map(|item| item.mac)
        .ok_or_else(|| Error::from("Failed to lookup mac for ip"))
}

fn rotate_file(filepath: &OsStr) {
    for i in (2..10).rev() {
        let mut from = filepath.to_os_string();
        from.push(format!(".{}", i-1));

        let mut to = filepath.to_os_string();
        to.push(format!(".{}", i));

        let _ = std::fs::rename(from, to);
    }

    let from = filepath.to_os_string();
    let mut to = filepath.to_os_string();
    to.push(".1");

    let _  = std::fs::rename(from, to);
}

fn format_mac(mac: &HwAddr) -> String {
    let octets = mac.octets();
    let mut mac_str = "".to_string();
    for octet in &octets {
        mac_str = format!("{}{:02x}", mac_str, octet);
    }

    mac_str
}


struct NetconsoleLogger {
    base_path: PathBuf,
    files: LinearMap<IpAddr, File>,
    file_history: ArrayDeque<[IpAddr; 5]>,
    udp_socket: UdpSocket,
}

impl NetconsoleLogger {
    fn new<T>(filepath: T, port: u16) -> NetconsoleLogger where PathBuf: From<T> {
        NetconsoleLogger {
            base_path: PathBuf::from(filepath),
            files: LinearMap::new(),
            file_history: ArrayDeque::new(),
            udp_socket: UdpSocket::bind(("0.0.0.0", port)).expect("failed to bind"),
        }
    }

    fn populate_file_for_ip(&mut self, ip: &IpAddr) -> Result<()> {
        let ip_index = self.file_history
            .iter()
            .enumerate()
            .find(|&(_, iter_ip)| iter_ip == ip)
            .map(|(idx, _)| idx);

        if let Some(ip_index) = ip_index {
            self.file_history.remove(ip_index);
        }

        let removed_ip = self.file_history.push_back(*ip);

        if let Some(removed_ip) = removed_ip {
            self.files.remove(&removed_ip);
        }

        if self.files.get(ip).is_some() {
            return Ok(())
        }

        let filepath = self.get_filename_for_ip(ip)?;

        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .append(true)
            .open(&filepath)
            .chain_err(|| "Failed to open file")?;

        self.files.insert(*ip, file);

        Ok(())
    }

    fn get_filename_for_ip(&self, ip: &IpAddr) -> Result<PathBuf> {
        let mac = get_mac_from_ip(ip)?;
        let mac_str = format_mac(&mac);
        Ok(self.base_path.join(format!("{}.log", &mac_str)))
    }


    fn get_file(&mut self, ip: &IpAddr) -> Result<&mut File>
    {
        self.populate_file_for_ip(ip)
            .chain_err(|| "Failed to insert file")?;

        Ok(self.files.get_mut(ip).unwrap())
    }

    fn write_incoming_line_to_file(&mut self) -> Result<()>
    {
        // Screw you if your MTU is larger than this
        let mut buf = [0; 1500];

        let (amnt, sender) = self.udp_socket
            .recv_from(&mut buf)
            .chain_err(|| "Failed to get udp message")?;

        let filepath = &self.get_filename_for_ip(&sender.ip())?;

        let file = OpenOptions::new()
            .create(true)
            .open(&filepath)
            .chain_err(|| "Failed to open file")?;

        let needs_rotate = match file.metadata() {
             Ok(metadata) => metadata.size() > 50 * 1024 * 1024,
             Err(_) => false,
        };

        if needs_rotate {
            rotate_file(filepath.as_os_str());
        }

        let file = self.get_file(&sender.ip())
            .chain_err(|| "Failed to get log file")?;

        let _ = file.write(&buf[0..amnt]);

        Ok(())
    }

    fn run(&mut self) {
        loop {
            if let Err(e) = self.write_incoming_line_to_file() {
                println!("{}", error_chain::ChainedError::display_chain(&e));
            }
        }
    }
}

fn main () {
    let log_path = env::args().nth(1)
        .unwrap_or_else(|| "".into());

    let mut netconsole_logger = NetconsoleLogger::new(log_path, 6666);
    netconsole_logger.run();
}
