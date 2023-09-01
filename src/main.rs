use crate::fs::File;
use byteorder::{ByteOrder, LittleEndian};
use rusb::{DeviceHandle, GlobalContext};
use std::fs;
use std::io::BufReader;
use std::io::Read;
use std::time;
use std::time::Duration;

const MAGIC: &[u8; 4] = b"DBI0";
const VENDOR_ID: u16 = 0x057E;
const ID_PRODUCT: u16 = 0x3000;
const CMD_ID_EXIT: u32 = 0;
//const CMD_ID_LIST_OLD: u16 = 1;
const CMD_ID_FILE_RANGE: u32 = 2;
const CMD_ID_LIST: u32 = 3;

//const CMD_TYPE_REQUEST: u16 = 0;
const CMD_TYPE_RESPONSE: u32 = 1;
const CMD_TYPE_ACK: u32 = 2;

fn main() {
    let a = connect_to_switch();

    match a {
        Ok(_) => println!("fine"),
        Err(e) => println!("error: {:?}", e),
    }
}

struct OpenedDevice {
    device: DeviceHandle<GlobalContext>,
    in_ep: u8,
    out_ep: u8,
}

impl OpenedDevice {
    fn read(&self, buf: &mut Vec<u8>) -> Result<usize, rusb::Error> {
        self.device
            .read_bulk(self.in_ep, buf, Duration::from_secs(10))
    }

    fn write(&self, buf: &mut Vec<u8>) -> Result<usize, rusb::Error> {
        self.device
            .write_bulk(self.out_ep, buf, Duration::from_secs(10))
    }
}

// Define a function that opens a USB device by its vendor ID and product ID
fn open_device(vid: u16, pid: u16) -> Result<OpenedDevice, rusb::Error> {
    let mut in_ep = 0;
    let mut out_ep = 0;

    // Get a list of the current USB devices
    let devices = rusb::devices()?;
    // Iterate over the devices
    for device in devices.iter() {
        // Get the device descriptor
        let device_desc = device.device_descriptor()?;
        // Check if the device matches the vendor ID and product ID
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

            // Open the device and return the handle
            return Ok(OpenedDevice {
                device: device.open()?,
                in_ep: in_ep,
                out_ep: out_ep,
            });
        }
    }
    // If no matching device is found, return an error
    Err(rusb::Error::NotFound)
}

// Define a function that runs some functions based on received instructions
fn run_functions(
    opened_device: &OpenedDevice,
    cmd: u32,
    data_size: u32,
) -> Result<(), rusb::Error> {
    // Match the command with different cases
    match cmd {
        CMD_ID_EXIT => Ok(process_exit_command()),
        CMD_ID_FILE_RANGE => Ok(proccess_file_range_command(
            &opened_device.device,
            opened_device.out_ep,
            opened_device.in_ep,
            data_size as u32,
        )),
        CMD_ID_LIST => Ok(process_list_command(
            &opened_device.device,
            opened_device.out_ep,
            opened_device.in_ep,
        )),
        _ => {
            // Run some custom functions here
            println!("Running custom functions for command {}", cmd);
            // Return Ok
            Ok(())
        }
    }
}

fn connect_to_switch() -> Result<(), rusb::Error> {
    let opened_device = open_device(VENDOR_ID, ID_PRODUCT)?;

    // Create a buffer with enough capacity
    let mut buf = vec![0; 1024];
    loop {
        opened_device.read(&mut buf)?;

        let cmd_id = LittleEndian::read_u32(&buf[8..10]);
        let data_size = LittleEndian::read_u32(&buf[12..16]);

        match run_functions(&opened_device, cmd_id, data_size) {
            // If successful, print a message and continue the loop
            Ok(_) => {
                println!("Functions run successfully for command {}", cmd_id);
                continue;
            }
            // If failed, print an error and break the loop
            Err(e) => {
                eprintln!("Error running functions for command {}: {}", cmd_id, e);
                break Err(e);
            }
        }
    }
}

fn process_exit_command() {
    println!("exit")
}

fn proccess_file_range_command(
    device: &DeviceHandle<GlobalContext>,
    out_ep: u8,
    in_ep: u8,
    data_size: u32,
) {
    let mut buffer: Vec<u8> = Vec::new();
    buffer.extend_from_slice(MAGIC);
    buffer.extend_from_slice(&CMD_TYPE_ACK.to_le_bytes());
    buffer.extend_from_slice(&CMD_ID_FILE_RANGE.to_le_bytes());
    buffer.extend_from_slice(&data_size.to_le_bytes());

    device
        .write_bulk(out_ep, &buffer, time::Duration::from_secs(10))
        .unwrap();

    buffer.clear();
    // Read from the bulk endpoint with a 10 second timeout
    let _n = device.read_bulk(in_ep, &mut buffer, time::Duration::from_secs(10));

    let range_size = LittleEndian::read_u32(&buffer[..4]);
    let range_offset = LittleEndian::read_u32(&buffer[4..12]);
    let nsp_name_len = LittleEndian::read_u32(&buffer[12..16]);
    let nsp_name = std::str::from_utf8(&buffer[16..]).unwrap();
    println!(
        "Range Size: {}, Range Offset: {}, Name len: {}, Name: {}",
        range_size, range_offset, nsp_name_len, nsp_name
    );

    buffer.clear();

    buffer.extend_from_slice(MAGIC);
    buffer.extend_from_slice(&CMD_TYPE_RESPONSE.to_le_bytes());
    buffer.extend_from_slice(&CMD_ID_FILE_RANGE.to_le_bytes());
    buffer.extend_from_slice(&data_size.to_le_bytes());

    device
        .write_bulk(out_ep, &buffer, time::Duration::from_secs(10))
        .unwrap();

    buffer.clear();
    let _n = device.read_bulk(in_ep, &mut buffer, time::Duration::from_secs(10));
    let ack = LittleEndian::read_u32(&buffer[..4]);
    let cmd_type = LittleEndian::read_u32(&buffer[4..8]);
    let cmd_id = LittleEndian::read_u32(&buffer[8..12]);
    let data_size = LittleEndian::read_u32(&buffer[12..16]);

    println!(
        "Cmd Type: {}, Command id: {}, Data size: {}",
        cmd_type, cmd_id, data_size
    );
    println!("{ack}");

    // Open the file and create a buffered reader
    let file = File::open("/home/pavel/Games/Nintendo/Super Mario 3D All-Stars [NSP]/Super Mario 3D All-Stars [010049900F546000][v0].nsp").unwrap();
    let mut reader: BufReader<File> = BufReader::new(file);

    // Create a buffer with the chunk size capacity
    let mut buffer = vec![0; data_size as usize];

    // Loop until the end of the file is reached
    loop {
        // Read a chunk of data from the file into the buffer
        let n = reader.read(&mut buffer).unwrap();

        // Break the loop if no more data is read
        if n == 0 {
            break;
        }

        // Write the buffer to the device using write_bulk method with a 10 second timeout
        device
            .write_bulk(out_ep, &buffer[..n], time::Duration::from_secs(10))
            .unwrap();
    }
}

fn process_list_command(device: &DeviceHandle<GlobalContext>, out_ep: u8, in_ep: u8) {
    let entries =
        fs::read_dir("/home/pavel/Games/Nintendo/Super Mario 3D All-Stars [NSP]").unwrap();
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

    let mut buffer: Vec<u8> = Vec::new();

    buffer.extend_from_slice(MAGIC);
    buffer.extend_from_slice(&CMD_TYPE_RESPONSE.to_le_bytes());
    buffer.extend_from_slice(&CMD_ID_LIST.to_le_bytes());

    let data_size = file_names.iter().map(|s| s.len() + 1).sum::<usize>();

    buffer.extend_from_slice(&(data_size as u32).to_le_bytes());

    device
        .write_bulk(out_ep, buffer.as_slice(), time::Duration::from_secs(10))
        .unwrap();

    buffer.clear();

    // Read from the bulk endpoint with a 10 second timeout
    let _n = device
        .read_bulk(in_ep, &mut buffer, time::Duration::from_secs(10))
        .unwrap();

    println!(
        "Cmd Type: {:?}, Command id: {:?}, Data size: {:?}",
        LittleEndian::read_u16(&buffer[4..8]),
        LittleEndian::read_u16(&buffer[8..12]),
        LittleEndian::read_u16(&buffer[12..16])
    );

    buffer.clear();

    for file_name in &file_names {
        buffer.extend_from_slice(file_name.as_bytes());
        buffer.push(b'\n');
    }
    device
        .write_bulk(out_ep, buffer.as_slice(), time::Duration::from_secs(50))
        .unwrap();
}
