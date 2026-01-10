use crate::socket::info::SocketInfo;
use log::info;

pub fn is_network_info(line: &str) -> bool {
    line.contains(" 005 ")
}

pub fn handle_network_info(socket_info: &SocketInfo, line: &str) {
    if let Some(network_part) = line.split_whitespace().find(|s| s.starts_with("NETWORK=")) {
        let network_name = network_part.trim_start_matches("NETWORK=");
        socket_info.set_network_name(network_name);
        info!("Socket {}: detected network name: {}", socket_info.socket, network_name);
    }
}
