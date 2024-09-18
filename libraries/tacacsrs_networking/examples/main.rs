use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tacacsrs_messages::packet::Packet;


#[tokio::main]
async fn main() {
    let addr = "127.0.0.1:8080";

    let (tcp_tx, mut tcp_rx) = mpsc::channel::<Packet>(32);
    let (bridge_tx, mut bridge_rx) = mpsc::channel::<Packet>(32);
    let (mut client, mut server) = tokio::io::duplex(64);



    // Start message sender loop
    tokio::spawn(async move {
        let _ = message_broker(tcp_tx, bridge_rx).await;
    });

    match TcpStream::connect(addr).await {
        Ok(mut stream) => {
            println!("Successfully connected to server at {}", addr);
            handle_connection(stream, addr).await?;
        }
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
}


async fn handle_connection(mut stream: TcpStream, addr: &str) -> anyhow::Result<()> {
    println!("Successfully connected to server at {}", addr);

    let (mut reader, mut writer) = stream.split();

    // let send_task = tokio::spawn(async move {
    //     writer.write_all(b"Hello, world!").await?;
    //     Ok::<_, anyhow::Error>(())
    // });

    // let receive_task = tokio::spawn(async move {
    //     let mut buffer = [0; 1024];
    //     let n = reader.read(&mut buffer).await?;
    //     println!("Received: {}", String::from_utf8_lossy(&buffer[..n]));
    //     Ok::<_, anyhow::Error>(())
    // });

    let write_task = write_handler(stream, sender_tx);
    let read_task = read_handler(stream, receiver_tx);

    tokio::try_join!(send_task, receive_task)?;

    Ok(())
}

async fn write_handler(mut stream: TcpStream, mut tx: mpsc::Sender<Packet>) {
    let mut buffer = [0; 8046];
    loop {
        // let n = stream.read(&mut buffer).await.unwrap();
        // let message = Packet::from_bytes(&buffer[..n]).unwrap();
        // tx.send(message).await.unwrap();
    }
}

async fn read_handler(mut stream: TcpStream, mut rx: mpsc::Receiver<Packet>) {
    while let Some(message) = rx.recv().await {
        //stream.write_all(&message.to_bytes()).await.unwrap();
    }
}

async fn message_broker(mut tx: mpsc::Sender<Packet>, mut rx: mpsc::Receiver<Packet>) {
    while let Some(message) = rx.recv().await {
        if let Err(e) = stream.write_all(&message).await {
            println!("Failed to send message: {}", e);
            break;
        }
    }
}