# Apoapsis Multiboot
Apoapsis Multiboot is a Rust implementation of the zyMultiboot protocol, which allows you to send firmware files over a network using multicast packets for various Zyxel manufactured devices. This specific implementation was made using the Huawei B2368-57 device as reference (Yes, it is Huawei brand but it was built by Zyxel).

## Features
- Send firmware files for RAS and/or LTE.
- Supports continuous stream mode for sending firmware files.
- Configurable wait time before sending the firmware.
- Specify the IP address of the network interface used to send multicast packets.

## Usage
``cargo run -- [--stream] [--wait <wait_time>] --local-ip <local_ip> [--upgrade-ras <ras_file>] [--upgrade-lte <lte_file>]``

### Options
- `--stream`: Send the firmware in a continuous stream mode. Again and again. (optional).
- `--wait <wait_time>`: Wait time (in seconds) before sending the firmware (optional, conflicts with `--stream`).
- `--local-ip <local_ip>`: IP address of the network interface that will be used to send the multicast packets (required).
- `--upgrade-ras <ras_file>`: Specify file to send as RAS file (optional, but either this or `--upgrade-lte` must be provided).
- `--upgrade-lte <lte_file>`: Specify file to send as LTE file (optional, but either this or `--upgrade-ras` must be provided).

## Example
``cargo run -- --wait 5 --local-ip 192.168.1.100 --upgrade-ras firmware.ras --upgrade-lte firmware.lte``
