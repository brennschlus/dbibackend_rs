use byteorder::{ByteOrder, LittleEndian};
use rusb::{DeviceHandle, Direction, GlobalContext};
use std::{
    convert::TryInto,
    env, fs,
    io::{BufReader, Read, Seek, SeekFrom},
    path::PathBuf,
    process,
    time::Duration,
};
use thiserror::Error;

/// Vendor and product IDs for the device.
const VENDOR_ID: u16 = 0x057E;
const PRODUCT_ID: u16 = 0x3000;
/// Buffer segment size for file transfers.
const BUFFER_SEGMENT_DATA_SIZE: u32 = 0x100000;
/// Expected magic header.
const MAGIC: [u8; 4] = *b"DBI0";

/// Command identifiers.
const CMD_ID_EXIT: u32 = 0;
const CMD_TYPE_RESPONSE: u32 = 1;
const CMD_ID_FILE_RANGE: u32 = 2;
const CMD_TYPE_ACK: u32 = 2;
const CMD_ID_LIST: u32 = 3;

#[derive(Error, Debug)]
enum DBIError {
    #[error("USB error: {0}")]
    Rusb(#[from] rusb::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    Parse(#[from] std::num::ParseIntError),
    #[error("UTF8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("Slice conversion error: {0}")]
    TryFromSlice(#[from] std::array::TryFromSliceError),
    #[error("Wrong header. Expected {expected:?}, found: {found:?}")]
    WrongHeader { expected: [u8; 4], found: [u8; 4] },
    #[error("Missing argument: expected folder path.")]
    MissingArgument,
}

/// A helper to build command buffers.
fn build_command_buffer(cmd_type: u32, cmd_id: u32, extra: Option<u32>) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16);
    buf.extend_from_slice(&MAGIC);
    buf.extend_from_slice(&cmd_type.to_le_bytes());
    buf.extend_from_slice(&cmd_id.to_le_bytes());
    let data = extra.unwrap_or(0);
    buf.extend_from_slice(&data.to_le_bytes());
    buf
}

/// Struct representing an open USB device.
struct OpenedDevice {
    device: DeviceHandle<GlobalContext>,
    in_ep: u8,
    out_ep: u8,
}

impl OpenedDevice {
    fn read(&self, size: usize) -> Result<Vec<u8>, DBIError> {
        let mut buf = vec![0u8; size];
        self.device
            .read_bulk(self.in_ep, &mut buf, Duration::from_secs(10))?;
        Ok(buf)
    }

    fn write(&self, buf: &[u8]) -> Result<usize, rusb::Error> {
        self.device.write_bulk(self.out_ep, buf, Duration::ZERO)
    }
}

/// Attempts to find and open the USB device.
fn open_device(vid: u16, pid: u16) -> Result<OpenedDevice, rusb::Error> {
    for device in rusb::devices()?.iter() {
        let desc = device.device_descriptor()?;
        if desc.vendor_id() == vid && desc.product_id() == pid {
            let config = device.active_config_descriptor()?;
            let interface = config.interfaces().next().ok_or(rusb::Error::NotFound)?;
            let setting = interface
                .descriptors()
                .next()
                .ok_or(rusb::Error::NotFound)?;
            let mut in_ep = 0;
            let mut out_ep = 0;
            for endpoint in setting.endpoint_descriptors() {
                match endpoint.direction() {
                    Direction::In => in_ep = endpoint.address(),
                    Direction::Out => out_ep = endpoint.address(),
                }
            }
            #[cfg(target_os = "macos")]
            let mut dev_handle = device.open()?;
            #[cfg(not(target_os = "macos"))]
            let dev_handle = device.open()?;
            #[cfg(target_os = "macos")]
            {
                dev_handle.detach_kernel_driver(setting.interface_number())?;
                dev_handle.claim_interface(setting.interface_number())?;
            }
            return Ok(OpenedDevice {
                device: dev_handle,
                in_ep,
                out_ep,
            });
        }
    }
    Err(rusb::Error::NotFound)
}

/// Runs the appropriate function based on the command id.
fn run_functions(
    device: &OpenedDevice,
    cmd_id: u32,
    data_size: u32,
    path: &PathBuf,
) -> Result<(), DBIError> {
    match cmd_id {
        CMD_ID_EXIT => process_exit_command(device),
        CMD_ID_FILE_RANGE => process_file_range_command(device, data_size, path),
        CMD_ID_LIST => process_list_command(device, path),
        other => {
            eprintln!("Unknown command type: {}", other);
            Err(rusb::Error::InvalidParam.into())
        }
    }
}

/// Connects to the nintendo switch and continuously processes commands.
fn connect_to_switch(path: &PathBuf) -> Result<(), DBIError> {
    let device = open_device(VENDOR_ID, PRODUCT_ID)?;
    loop {
        let buf = device.read(16)?;
        if buf.len() < 16 {
            return Err(rusb::Error::InvalidParam.into());
        }
        if &buf[..4] != MAGIC {
            let found: [u8; 4] = buf[..4].try_into()?;
            return Err(DBIError::WrongHeader {
                expected: MAGIC,
                found,
            });
        }
        // Read the command id and data size from the buffer.
        let cmd_id = LittleEndian::read_u32(&buf[8..12]);
        let data_size = LittleEndian::read_u32(&buf[12..16]);
        if let Err(e) = run_functions(&device, cmd_id, data_size, path) {
            eprintln!("Error running command {}: {}", cmd_id, e);
            return Err(e);
        }
        println!("Successfully processed command {}", cmd_id);
    }
}

/// Sends an exit command to the device.
fn process_exit_command(device: &OpenedDevice) -> Result<(), DBIError> {
    let buffer = build_command_buffer(CMD_TYPE_RESPONSE, CMD_ID_EXIT, None);
    device.write(&buffer)?;
    process::exit(0);
}

/// Processes the file range command.
fn process_file_range_command(
    device: &OpenedDevice,
    data_size: u32,
    path: &PathBuf,
) -> Result<(), DBIError> {
    // Acknowledge the command.
    let ack_buffer = build_command_buffer(CMD_TYPE_ACK, CMD_ID_FILE_RANGE, None);
    device.write(&ack_buffer)?;
    let buf = device.read(data_size as usize)?;
    // Safely slice the buffer according to expected sizes.
    if buf.len() < 16 {
        return Err(rusb::Error::InvalidParam.into());
    }
    let range_size = LittleEndian::read_u32(&buf[0..4]);
    let range_offset = LittleEndian::read_u64(&buf[4..12]);
    let nsp_name_len = LittleEndian::read_u32(&buf[12..16]) as usize;
    if buf.len() < 16 + nsp_name_len {
        return Err(rusb::Error::InvalidParam.into());
    }
    let nsp_name = std::str::from_utf8(&buf[16..16 + nsp_name_len])?;
    println!(
        "Range Size: {}, Range Offset: {}, Name len: {}, Name: {}",
        range_size, range_offset, nsp_name_len, nsp_name
    );

    let response_buffer =
        build_command_buffer(CMD_TYPE_RESPONSE, CMD_ID_FILE_RANGE, Some(range_size));
    device.write(&response_buffer)?;

    // Read a follow-up response (e.g., ACK details)
    let followup = device.read(16)?;
    let ack = LittleEndian::read_u32(&followup[0..4]);
    let cmd_type = LittleEndian::read_u32(&followup[4..8]);
    let cmd_id = LittleEndian::read_u32(&followup[8..12]);
    let data_size = LittleEndian::read_u32(&followup[12..16]);
    println!(
        "Ack: {}, Cmd Type: {}, Cmd ID: {}, Data Size: {}",
        ack, cmd_type, cmd_id, data_size
    );

    // Build the full path and open the file.
    let mut full_path = PathBuf::from(path);
    full_path.push(nsp_name);
    let file = fs::File::open(full_path)?;
    let mut reader = BufReader::new(file);
    reader.seek(SeekFrom::Start(range_offset))?;
    let mut curr_off = 0u32;
    while curr_off < range_size {
        let mut chunk_size = BUFFER_SEGMENT_DATA_SIZE;
        if curr_off + chunk_size > range_size {
            chunk_size = range_size - curr_off;
        }
        let mut buffer = vec![0u8; chunk_size as usize];
        reader.read_exact(&mut buffer)?;
        device.write(&buffer)?;
        curr_off += chunk_size;
    }
    Ok(())
}

/// Processes the list command by reading the directory contents.
fn process_list_command(device: &OpenedDevice, path: &PathBuf) -> Result<(), DBIError> {
    let entries = fs::read_dir(path)?;
    let file_names: Vec<String> = entries
        .filter_map(|entry| {
            entry.ok().and_then(|e| {
                let p = e.path();
                if p.is_file() {
                    p.file_name()
                        .and_then(|os_str| os_str.to_str().map(|s| s.to_owned()))
                } else {
                    None
                }
            })
        })
        .collect();

    // Prepare response header.
    let mut header = build_command_buffer(CMD_TYPE_RESPONSE, CMD_ID_LIST, None);
    let data_size: u32 = file_names.iter().map(|s| (s.len() + 1) as u32).sum();
    header.extend_from_slice(&data_size.to_le_bytes());
    device.write(&header)?;
    // Read an acknowledgement (assuming a 16-byte response structure).
    let ack_buf = device.read(16)?;
    println!("List command ACK details: {:?}", &ack_buf[4..16]);
    // Build payload with file names separated by newline.
    let payload = file_names.join("\n");
    device.write(payload.as_bytes())?;
    Ok(())
}

fn main() -> Result<(), DBIError> {
    // Use .nth(1) to get the first argument for the folder path.
    let folder = env::args().nth(1).ok_or(DBIError::MissingArgument)?;
    let canonical_path = PathBuf::from(folder).canonicalize()?;
    connect_to_switch(&canonical_path)
}
