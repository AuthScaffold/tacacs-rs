
use std::sync::Arc;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tacacsrs_networking::connection;



#[tokio::main]
async fn main() {
    let connection_info = connection::ConnectionInfo {
        ip_socket: SocketAddr::new(IpAddr::V4("192.168.1.32".parse::<Ipv4Addr>().unwrap()), 49)
    };

    let connection = Arc::new(connection::Connection::new(&connection_info));

    match connection.clone().connect().await {
        Ok(_) => {
            println!("Successfully connected to server at {}", connection_info.ip_socket);
        }
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }

    let session = connection.create_session().await.unwrap();

}
