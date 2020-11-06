#[macro_use]
extern crate anyhow;
extern crate cached;
extern crate crossbeam;
extern crate pnet;
extern crate pretty_env_logger;
#[macro_use]
extern crate log;

use cached::stores::SizedCache;
use cached::Cached;
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::DataLinkReceiver;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::{Packet, PacketSize, PrimitiveValues};
use pnet::util::MacAddr;

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use anyhow::{Context, Result};

struct InterfaceLogger {
    base_path: PathBuf,
    file_cache: Arc<Mutex<SizedCache<MacAddr, File>>>,
    udp_port: u16,
    datalink_rx: Box<dyn DataLinkReceiver + 'static>,
    mac_addr: MacAddr,
}

impl InterfaceLogger {
    fn get_file_name(base_path: &Path, mac: MacAddr) -> PathBuf {
        let (a, b, c, d, e, f) = mac.to_primitive_values();
        let filename = format!("{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.log", a, b, c, d, e, f);
        base_path.join(filename)
    }

    fn create_file(base_path: &Path, mac: MacAddr) -> File {
        let filename = Self::get_file_name(base_path, mac);
        std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(filename)
            .unwrap()
    }

    fn get_rolled_file_name(base_file_name: &Path, idx: usize) -> PathBuf {
        match idx {
            0 => base_file_name.to_path_buf(),
            _ => {
                let mut rolled_name = base_file_name.as_os_str().to_os_string();
                rolled_name.push(format!(".{}", idx));
                PathBuf::from(rolled_name)
            }
        }
    }

    fn roll_file(base_file_name: &Path) -> Result<bool> {
        let metadata =
            std::fs::metadata(base_file_name)
                .context("Failed to get metadata")?;

        if metadata.len() < 10 * 1024 * 1024 {
            return Ok(false);
        }

        debug!("Rolling file");

        for i in (0..9).rev() {
            let new_name = Self::get_rolled_file_name(base_file_name, i + 1);
            let old_name = Self::get_rolled_file_name(base_file_name, i);
            if let Err(e) = std::fs::rename(&old_name, &new_name) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    return Err(anyhow!(format!(
                        "Failed to roll {} into {} ({})",
                        old_name.into_os_string().into_string().unwrap(),
                        new_name.into_os_string().into_string().unwrap(),
                        e
                    )));
                }
            }
        }

        Ok(true)
    }

    fn get_file<'a>(
        file_cache: &'a mut SizedCache<MacAddr, File>,
        base_path: &Path,
        mac: MacAddr,
    ) -> &'a File {
        match Self::roll_file(&Self::get_file_name(base_path, mac)) {
            Ok(true) => (),
            Ok(false) => {
                file_cache.cache_remove(&mac);
            },
            Err(e) => {
                error!("{}", e);
            },
        }

        match file_cache.cache_get(&mac) {
            Some(x) => unsafe { std::mem::transmute::<&File, &'a File>(x) },
            None => {
                let file = Self::create_file(base_path, mac);
                file_cache.cache_set(mac, file);
                file_cache.cache_get(&mac).unwrap()
            }
        }
    }

    fn write_incoming_line_to_file(&mut self) -> Result<()> {
        let packet = self
            .datalink_rx
            .next()
            .context("Invalid packet")?;

        let ethernet_packet =
            EthernetPacket::new(packet)
            .context("No ethernet packet")?;

        debug!("{:?}", ethernet_packet);

        if ethernet_packet.get_destination() != self.mac_addr {
            debug!("Ethernet frame not meant for us, returning early");
            return Ok(());
        }

        let ipv4_packet = match ethernet_packet.get_ethertype() {
            EtherTypes::Ipv4 => Ipv4Packet::new(ethernet_packet.payload())
                .context("No ethernet payload")?,
            _ => {
                info!("Unhandled ethernet packet type");
                return Ok(());
            }
        };

        debug!("{:?}", ipv4_packet);

        let udp_packet = match ipv4_packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Udp => UdpPacket::new(ipv4_packet.payload())
                .context("No IPv4 payload")?,
            _ => {
                debug!("Ipv4 packet is not udp, returning early");
                return Ok(());
            }
        };

        debug!("{:?}", udp_packet);

        if udp_packet.get_destination() != self.udp_port {
            debug!("Not the requested udp port, returning early");
            return Ok(());
        }

        let mac = ethernet_packet.get_source();
        let payload_size = udp_packet.get_length() as usize - udp_packet.packet_size() as usize;
        let payload = &udp_packet.payload()[..payload_size];
        {
            let mut file_cache = self.file_cache.lock().unwrap();
            let mut file = Self::get_file(&mut file_cache, &self.base_path, mac);

            file.write(payload)
                .context("Failed to write payload to file")?;
        }

        Ok(())
    }

    pub fn run(&mut self) {
        loop {
            if let Err(e) = self.write_incoming_line_to_file() {
                error!("{:?}", e);
            }
        }
    }
}

struct NetconsoleLogger {
    interface_loggers: Vec<InterfaceLogger>,
}

impl NetconsoleLogger {
    fn new<T>(filepath: T, port: u16) -> NetconsoleLogger
    where
        PathBuf: From<T>,
    {
        let file_cache = Arc::new(Mutex::new(SizedCache::with_size(5)));
        let base_path = PathBuf::from(filepath);
        let interface_loggers = datalink::interfaces()
            .into_iter()
            .filter(|iface| iface.mac.is_some())
            .filter_map(|iface| {
                datalink::channel(&iface, Default::default())
                    .ok()
                    .map(|x| (iface.mac.unwrap(), x))
            })
            .filter_map(|(mac, channel)| match channel {
                Ethernet(_, rx) => Some((mac, rx)),
                _ => None,
            })
            .map(|(mac, channel)| InterfaceLogger {
                base_path: base_path.clone(),
                file_cache: Arc::clone(&file_cache),
                udp_port: port,
                datalink_rx: channel,
                mac_addr: mac,
            })
            .collect();

        NetconsoleLogger { interface_loggers }
    }

    fn run(&mut self) {
        crossbeam::scope(|scope| {
            for interface_logger in self.interface_loggers.iter_mut() {
                scope.spawn(move |_| interface_logger.run());
            }
        })
        .unwrap();
    }
}

fn main() {
    pretty_env_logger::init();

    let log_path = env::args().nth(1).unwrap_or_else(|| "".into());

    let mut netconsole_logger = NetconsoleLogger::new(log_path, 6666);
    netconsole_logger.run();
}
