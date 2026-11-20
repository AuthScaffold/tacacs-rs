//! A small HTTP/1.1 server for CRL fetch tests.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The response of one route.
#[derive(Clone)]
pub(crate) enum Response {
    /// Status 200 with a body and a Content-Length.
    Body(Vec<u8>),
    /// A status without a body.
    Status(u16),
    /// Status 200 with a body that arrives after a delay.
    Delayed(Vec<u8>, Duration),
    /// Status 200 with a body of this size and no Content-Length.
    Unbounded(usize),
    /// Status 200 with this Content-Length and no body.
    Announced(u64),
    /// Headers, then a part of the body, then nothing.
    Stall,
}

#[derive(Default)]
struct State {
    routes: HashMap<String, Response>,
    requests: HashMap<String, usize>,
}

/// A running test server on 127.0.0.1.
#[derive(Clone)]
pub(crate) struct Server {
    address: SocketAddr,
    state: Arc<Mutex<State>>,
}

impl Server {
    pub(crate) async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(State::default()));
        let shared = Arc::clone(&state);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve(stream, Arc::clone(&shared)));
            }
        });
        Self { address, state }
    }

    /// Returns the URL of `path` on this server.
    pub(crate) fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }

    /// Returns an allowlist pattern that covers this server.
    pub(crate) fn pattern(&self) -> String {
        format!("http://{}/**", self.address)
    }

    pub(crate) fn route(&self, path: &str, response: Response) {
        self.state
            .lock()
            .unwrap()
            .routes
            .insert(path.to_owned(), response);
    }

    pub(crate) fn requests(&self, path: &str) -> usize {
        self.state
            .lock()
            .unwrap()
            .requests
            .get(path)
            .copied()
            .unwrap_or(0)
    }
}

/// Returns a URL on a local port without a listener.
pub(crate) async fn closed_url(path: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    format!("http://{address}{path}")
}

async fn serve(mut stream: TcpStream, state: Arc<Mutex<State>>) {
    let mut request = Vec::new();
    let mut buffer = [0u8; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        match stream.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(read) => request.extend_from_slice(&buffer[..read]),
        }
    }
    let text = String::from_utf8_lossy(&request);
    let path = text.split_whitespace().nth(1).unwrap_or("/").to_owned();
    let response = {
        let mut state = state.lock().unwrap();
        *state.requests.entry(path.clone()).or_default() += 1;
        state.routes.get(&path).cloned()
    };
    let head = |status: u16, length: Option<u64>| {
        let mut head = format!("HTTP/1.1 {status} Test\r\nConnection: close\r\n");
        if let Some(length) = length {
            head.push_str(&format!("Content-Length: {length}\r\n"));
        }
        head.push_str("\r\n");
        head.into_bytes()
    };
    let length = |body: &[u8]| Some(u64::try_from(body.len()).unwrap());
    let _ = match response.unwrap_or(Response::Status(404)) {
        Response::Body(body) => {
            let _ = stream.write_all(&head(200, length(&body))).await;
            stream.write_all(&body).await
        }
        Response::Status(status) => stream.write_all(&head(status, Some(0))).await,
        Response::Delayed(body, delay) => {
            let _ = stream.write_all(&head(200, length(&body))).await;
            tokio::time::sleep(delay).await;
            stream.write_all(&body).await
        }
        Response::Unbounded(size) => {
            let _ = stream.write_all(&head(200, None)).await;
            stream.write_all(&vec![0x30; size]).await
        }
        Response::Announced(size) => stream.write_all(&head(200, Some(size))).await,
        Response::Stall => {
            let _ = stream.write_all(&head(200, Some(4096))).await;
            let _ = stream.write_all(&[0x30; 16]).await;
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok(())
        }
    };
    let _ = stream.shutdown().await;
}
