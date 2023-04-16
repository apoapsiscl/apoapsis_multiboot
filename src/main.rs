// SPDX-License-Identifier: MIT
// Copyright (c) 2023 Carlos Pizarro (Apoapsis SpA) <kr105@kr105.com>
// For full license details, see the LICENSE file in the repository root.

use bytes::{BufMut, BytesMut};
use clap::{value_parser, Arg, ArgGroup, Command};
use socket2::{Domain, Protocol, Socket, Type};
use std::mem::size_of;
use std::net::{Ipv4Addr, SocketAddr};
use std::{thread, time};

const MULTIBOOT_SIGNATURE: [u8; 4] = [b'z', b'y', b'x', 0];
const MULTIBOOT_PACKET_SIZE: usize = 1400;
const MULTIBOOT_MULTICAST_ADDRESS: &str = "225.0.0.0:5631";

pub struct MultibootT {
    signature: [u8; 4],
    check_sum: u16,
    id: u32,
    data_len: u32,
    file_len: u32,
    file_flag: u32,
    country_code: u16,
    debug_flag: u8,
    reserve1: u8,
    reserve2: u32,
    data: [u8; MULTIBOOT_PACKET_SIZE],
}

impl Default for MultibootT {
    fn default() -> Self {
        Self::new()
    }
}

impl MultibootT {
    pub fn new() -> Self {
        MultibootT {
            signature: MULTIBOOT_SIGNATURE,
            check_sum: 0,
            id: 0,
            data_len: 0,
            file_len: 0,
            file_flag: 0,
            country_code: 0,
            debug_flag: 0,
            reserve1: 0,
            reserve2: 0,
            data: [0; MULTIBOOT_PACKET_SIZE],
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut bytes = BytesMut::with_capacity(size_of::<MultibootT>());

        bytes.put_slice(&self.signature);
        bytes.put_u16(self.check_sum);
        bytes.put_u32(self.id);
        bytes.put_u32(self.data_len);
        bytes.put_u32(self.file_len);
        bytes.put_u32(self.file_flag);
        bytes.put_u16(self.country_code);
        bytes.put_u8(self.debug_flag);
        bytes.put_u8(self.reserve1);
        bytes.put_u32(self.reserve2);
        bytes.put_slice(&self.data);

        bytes.to_vec()
    }
}

#[allow(unused)]
enum UpgradeFileType {
    BootLoader = 1,
    UsrConfig = 2,
    Ras = 4,
    ProcessEngineerDebugFlag = 7,
    Lte = 8,
}

fn main() {
    let cmd = Command::new("Apoapsis Multiboot")
        .version("1.0")
        .author("Carlos Pizarro <kr105@kr105.com>")
        .about("Implementation of the zyMultiboot protocol")
        .arg(
            Arg::new("stream")
                .long("stream")
                .help("Send the firmware in a continuous stream mode")
                .default_missing_value("false")
                .default_value("false")
                .num_args(0..=1)
                .value_parser(value_parser!(bool)),
        )
        .arg(
            Arg::new("wait")
                .long("wait")
                .help("Wait time (in seconds) for sending the firmware")
                .default_missing_value("0")
                .default_value("0")
                .value_parser(value_parser!(u8))
                .conflicts_with("stream"),
        )
        .arg(
            Arg::new("local_ip")
                .long("local-ip")
                .help("IP address of the network interface that will be used to send the multicast packets")
                .required(true)
                .value_parser(value_parser!(Ipv4Addr))
        )
        .arg(
            Arg::new("upgrade_ras")
                .long("upgrade-ras")
                .help("Specify file to send as RAS file")
                .default_value("")
                .value_parser(value_parser!(String))
        )
        .arg(
            Arg::new("upgrade_lte")
                .long("upgrade-lte")
                .help("Specify file to send as LTE file")
                .default_value("")
                .value_parser(value_parser!(String))
        )
        .group(ArgGroup::new("upgrade")
            .args(["upgrade_ras", "upgrade_lte"])
            .required(true)
            .multiple(true)
        );

    let matches = cmd.get_matches();

    // It is safe to unwrap the arguments since all of them will have a value
    let stream = matches.get_one::<bool>("stream").unwrap();
    let wait_time = matches.get_one::<u8>("wait").unwrap();
    let local_ip = matches.get_one::<Ipv4Addr>("local_ip").unwrap();
    let upgrade_ras = matches.get_one::<String>("upgrade_ras").unwrap();
    let upgrade_lte = matches.get_one::<String>("upgrade_lte").unwrap();

    // New UDP socket
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .expect("Failed to create UDP socket");

    // Set the interface that will route multicast packets
    socket.set_multicast_if_v4(local_ip).unwrap();

    // Bind into the interface to make 100% sure that the packets will go out from here
    let address: SocketAddr = SocketAddr::from((*local_ip, 0));
    let address = address.into();
    socket.bind(&address).unwrap();

    // Setup socket
    socket.set_multicast_loop_v4(false).unwrap();
    socket.set_broadcast(true).unwrap();

    // Sending mode flag
    let mut mode: u8 = 0;

    // Read RAS file if specified
    let mut ras_file: Option<Vec<u8>> = None;
    if !upgrade_ras.is_empty() {
        ras_file = match std::fs::read(upgrade_ras) {
            Ok(bytes) => Some(bytes),
            Err(e) => {
                eprintln!("{}", e);
                None
            }
        };

        // Update the mode flag
        mode |= UpgradeFileType::Ras as u8;
    }

    // Read LTE file if specified
    let mut lte_file: Option<Vec<u8>> = None;
    if !upgrade_lte.is_empty() {
        lte_file = match std::fs::read(upgrade_lte) {
            Ok(bytes) => Some(bytes),
            Err(e) => {
                eprintln!("{}", e);
                None
            }
        };

        // Update the mode flag
        mode |= UpgradeFileType::Lte as u8;
    }

    // Wait the specified amount of seconds before starting the process
    thread::sleep(time::Duration::from_secs(u64::from(*wait_time)));

    loop {
        if let Some(ref ras) = ras_file {
            // Send RAS file
            send_file(&socket, mode, UpgradeFileType::Ras, ras);
        }

        if let Some(ref lte) = lte_file {
            // Send LTE file
            send_file(&socket, mode, UpgradeFileType::Lte, lte);
        }

        // If stream mode is not specified, send only once
        if !stream {
            break;
        }
    }

    println!("Bye :)");
}

fn send_file(socket: &Socket, finish_file_flag: u8, file_type: UpgradeFileType, file: &[u8]) {
    let mut packet = MultibootT::new();

    packet.file_len = u32::try_from(file.len()).unwrap();

    // The second-to-last byte = upgradeFileType = the current file being sent
    // In the last byte, all the file types to be flashed are stored (type1 | type2 | type3)
    packet.file_flag = ((file_type as u32) << 8) | u32::from(finish_file_flag);

    let mut bytes_sent = 0;
    let mut packet_id = 0;

    let dest_address: SocketAddr = MULTIBOOT_MULTICAST_ADDRESS.parse().unwrap();
    let dest_address = dest_address.into();

    loop {
        packet.id = packet_id;

        let remaining_bytes = file.len() - bytes_sent;

        // How many bytes we are going to send on this pass
        let sending_bytes = std::cmp::min(remaining_bytes, MULTIBOOT_PACKET_SIZE);

        packet.data_len = u32::try_from(sending_bytes).unwrap();

        // Load data into packet
        packet.data[..sending_bytes]
            .copy_from_slice(&file[bytes_sent..(bytes_sent + sending_bytes)]);

        // Calculate checksum
        let mut checksum: u32 = 0;

        for i in 0..sending_bytes {
            checksum += u32::from(packet.data[i]);
        }

        // We need only the last 16 bits of the u32
        checksum = ((checksum >> 16) + checksum) & 0xFFFF;
        packet.check_sum = checksum as u16;

        socket.send_to(&packet.to_vec(), &dest_address).unwrap();

        // Update for the next pass
        packet_id += 1;
        bytes_sent += sending_bytes;

        if bytes_sent as u32 >= packet.file_len {
            break;
        }
    }
}
