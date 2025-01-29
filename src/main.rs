use crate::fs::File;
use byteorder::{ByteOrder, LittleEndian};
use rusb::{DeviceHandle, GlobalContext};
use std::array::TryFromSliceError;
use std::fs;

use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::process::exit;
use std::time::Duration;
use thiserror::Error;

const VENDOR_ID: u16 = 0x057E;
const ID_PRODUCT: u16 = 0x3000;
const BUFFER_SEGMENT_DATA_SIZE: u32 = 0x100000;

const MAGIC: [u8; 4] = *b"DBI0";
const CMD_ID_EXIT: [u8; 4] = 0u32.to_le_bytes(); // 0 to LittleEndian
const CMD_TYPE_RESPONSE: [u8; 4] = 1u32.to_le_bytes(); // 1 to LittleEndian
const CMD_ID_FILE_RANGE: [u8; 4] = 2u32.to_le_bytes(); // 2 to LittleEndian
const CMD_TYPE_ACK: [u8; 4] = 2u32.to_le_bytes(); // 2 to LittleEndian
const CMD_ID_LIST: [u8; 4] = 3u32.to_le_bytes(); // 3 to LittleEndian

#[derive(Error, Debug)]
enum DBIError {
    #[error("rusb error: {0}")]
    Rusb(#[from] rusb::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse error: {0}")]
    Parse(#[from] std::num::ParseIntError),
    #[error("utf8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("try into error: {0})")]
    TryFromSlice(#[from] TryFromSliceError),
    #[error("wrong header. expected {:?}, found: {:?}", expected, found)]
    WrongHeader { expected: [u8; 4], found: [u8; 4] },
}

fn main() -> Result<(), DBIError> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Excepted folder path");
        exit(0);
    }

    let path: &String = &args[1];
    let path = PathBuf::from(path).canonicalize()?;

    let switch_connection = connect_to_switch(&path);

    match switch_connection {
        Ok(_) => println!("fine"),
        Err(e) => eprintln!("error: {:?}", e),
    };
    Ok(())
}

struct OpenedDevice {
    device: DeviceHandle<GlobalContext>,
    in_ep: u8,
    out_ep: u8,
}

impl OpenedDevice {
    fn read(&self, size: usize) -> Result<Vec<u8>, DBIError> {
        let mut buf: Vec<u8> = vec![0; size];
        self.device
            .read_bulk(self.in_ep, &mut buf, Duration::from_secs(10))?;
        Ok(buf)
    }

    fn write(&self, buf: Vec<u8>) -> Result<usize, rusb::Error> {
        self.device.write_bulk(self.out_ep, &buf, Duration::ZERO)
    }
}

fn open_device(vid: u16, pid: u16) -> Result<OpenedDevice, rusb::Error> {
    let mut in_ep = 0;
    let mut out_ep = 0;

    let devices = rusb::devices()?;
    for device in devices.iter() {
        let device_desc = device.device_descriptor()?;
        if device_desc.vendor_id() == vid && device_desc.product_id() == pid {
            let config = device.active_config_descriptor()?;

            let interface = config.interfaces().next().ok_or(rusb::Error::NotFound)?;
            let setting = interface
                .descriptors()
                .next()
                .ok_or(rusb::Error::NotFound)?;

            for endpoint in setting.endpoint_descriptors() {
                match endpoint.direction() {
                    rusb::Direction::In => in_ep = endpoint.address(),
                    rusb::Direction::Out => out_ep = endpoint.address(),
                }
            }

            #[cfg(target_os = "macos")]
            let mut open_device = device.open()?;

            #[cfg(not(target_os = "macos"))]
            let open_device = device.open()?;

            #[cfg(target_os = "macos")]
            {
                open_device.detach_kernel_driver(setting.interface_number())?;
                open_device.claim_interface(setting.interface_number())?;
            }

            return Ok(OpenedDevice {
                device: open_device,
                in_ep,
                out_ep,
            });
        }
    }
    Err(rusb::Error::NotFound)
}

fn run_functions(
    opened_device: &OpenedDevice,
    cmd: [u8; 4],
    data_size: u32,
    path: &PathBuf,
) -> Result<(), DBIError> {
    match cmd {
        CMD_ID_EXIT => {
            process_exit_command(opened_device)?;
            Ok(())
        }
        CMD_ID_FILE_RANGE => {
            proccess_file_range_command(opened_device, data_size, path)?;
            Ok(())
        }
        CMD_ID_LIST => {
            process_list_command(opened_device, path)?;
            Ok(())
        }
        _ => {
            println!("Unknown command type {:?}", cmd);
            Err(DBIError::Rusb(rusb::Error::InvalidParam))
        }
    }
}

fn connect_to_switch(path: &PathBuf) -> Result<(), DBIError> {
    let opened_device = open_device(VENDOR_ID, ID_PRODUCT)?;

    loop {
        let buf = opened_device.read(16)?;

        if buf.len() < 16 {
            return Err(DBIError::Rusb(rusb::Error::InvalidParam));
        }

        if !buf.starts_with(&MAGIC) {
            let found: [u8; 4] = buf[..4].try_into()?;
            return Err(DBIError::WrongHeader {
                expected: MAGIC,
                found,
            });
        }

        let cmd_id = LittleEndian::read_u32(&buf[8..12]);
        let data_size = LittleEndian::read_u32(&buf[12..16]);

        match run_functions(&opened_device, cmd_id.to_le_bytes(), data_size, path) {
            Ok(_) => {
                println!("Functions run successfully for command {}", cmd_id);
                continue;
            }
            Err(e) => {
                eprintln!("Error running functions for command {}: {}", cmd_id, e);
                break Err(e);
            }
        }
    }
}

fn process_exit_command(device: &OpenedDevice) -> Result<(), DBIError> {
    let buffer: Vec<u8> = [MAGIC, CMD_TYPE_RESPONSE, CMD_ID_EXIT, CMD_ID_EXIT].concat();

    device.write(buffer)?;
    exit(1);
}

fn proccess_file_range_command(
    device: &OpenedDevice,
    data_size: u32,
    path: &PathBuf,
) -> Result<(), DBIError> {
    let buffer: Vec<u8> = [MAGIC, CMD_TYPE_ACK, CMD_ID_FILE_RANGE].concat();

    device.write(buffer)?;

    let buf = device.read(data_size as usize)?;

    let range_size = LittleEndian::read_u32(&buf[..4]);
    let range_offset = LittleEndian::read_u64(&buf[4..12]);
    let nsp_name_len = LittleEndian::read_u32(&buf[12..16]);
    let nsp_name = std::str::from_utf8(&buf[16..])?;
    println!(
        "Range Size: {}, Range Offset: {}, Name len: {}, Name: {}",
        range_size, range_offset, nsp_name_len, nsp_name
    );

    let buffer: Vec<u8> = [
        MAGIC,
        CMD_TYPE_RESPONSE,
        CMD_ID_FILE_RANGE,
        range_size.to_le_bytes(),
    ]
    .concat();

    device.write(buffer)?;

    let buf = device.read(16)?;
    let ack = LittleEndian::read_u32(&buf[..4]);
    let cmd_type = LittleEndian::read_u32(&buf[4..8]);
    let cmd_id = LittleEndian::read_u32(&buf[8..12]);
    let data_size = LittleEndian::read_u32(&buf[12..16]);

    println!(
        "Cmd Type: {}, Command id: {}, Data size: {}",
        cmd_type, cmd_id, data_size
    );
    println!("{ack}");

    let mut full_path = PathBuf::from(path);
    full_path.push(nsp_name);

    let file = File::open(full_path)?;
    let mut reader: BufReader<File> = BufReader::new(file);

    reader.seek(SeekFrom::Start(range_offset))?;
    let mut curr_off: u32 = 0x0;
    let end_off = range_size;
    let mut read_size: u32 = BUFFER_SEGMENT_DATA_SIZE;

    while curr_off < end_off {
        if curr_off + read_size >= end_off {
            read_size = end_off - curr_off;
        }

        let mut buffer: Vec<u8> = vec![0; read_size as usize];

        reader.read_exact(&mut buffer)?;

        device.write(buffer)?;
        curr_off += read_size;
    }

    Ok(())
}

fn process_list_command(device: &OpenedDevice, path: &PathBuf) -> Result<(), DBIError> {
    let entries = fs::read_dir(path)?;
    let file_names: Vec<String> = entries
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            if path.is_file() {
                path.file_name()?.to_str().map(|s| s.to_owned())
            } else {
                None
            }
        })
        .collect();

    let mut buffer: Vec<u8> = [MAGIC, CMD_TYPE_RESPONSE, CMD_ID_LIST].concat();

    let data_size = file_names.iter().map(|s| s.len() + 1).sum::<usize>();

    buffer.extend_from_slice(&(data_size as u32).to_le_bytes());

    device.write(buffer)?;

    let buf = device.read(16)?;

    println!(
        "Cmd Type: {:?}, Command id: {:?}, Data size: {:?}",
        LittleEndian::read_u16(&buf[4..8]),
        LittleEndian::read_u16(&buf[8..12]),
        LittleEndian::read_u16(&buf[12..16])
    );

    let mut buffer: Vec<u8> = vec![];

    for file_name in &file_names {
        buffer.extend_from_slice(file_name.as_bytes());
        buffer.push(b'\n');
    }

    device.write(buffer)?;

    Ok(())
}
