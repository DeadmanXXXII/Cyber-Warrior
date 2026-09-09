use crate::log::SharedLog;
use std::net::{IpAddr, TcpStream};
use std::time::Duration;

/// Scans a range of ports on `target` for a quick "what's exposed on my own
/// device/router" check. Requires `authorized == true`, which the GUI only
/// sets after the user explicitly checks a box confirming they own or are
/// authorized to test the target — this function refuses to run otherwise.
pub fn scan(
    target: IpAddr,
    start_port: u16,
    end_port: u16,
    authorized: bool,
    log: &SharedLog,
) -> Result<Vec<u16>, String> {
    if !authorized {
        let msg = "Port scan refused: authorization checkbox not set".to_string();
        log.alert("PortScanner", &msg);
        return Err(msg);
    }

    log.info(
        "PortScanner",
        format!("Scanning {target} ports {start_port}-{end_port}"),
    );

    let mut open_ports = Vec::new();
    for port in start_port..=end_port {
        if TcpStream::connect_timeout(&(target, port).into(), Duration::from_millis(300)).is_ok() {
            open_ports.push(port);
            log.warn("PortScanner", format!("{target}:{port} is open"));
        }
    }

    log.info(
        "PortScanner",
        format!("Scan of {target} complete: {} open port(s)", open_ports.len()),
    );
    Ok(open_ports)
}
