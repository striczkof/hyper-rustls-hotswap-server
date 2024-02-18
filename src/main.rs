// Extremely primitive hyper-based HTTP and HTTPS/TLS server with TLS hotswapping capability.
// Copyright (C) 2024, Alvin Peters
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
mod tls;

use std::io;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response};
use hyper::service::service_fn;
use tokio::net::TcpListener;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rustls::ServerConfig;
use tokio::{join, select};
use tokio::runtime::Runtime;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

static INDEX: &[u8] = b"The Index service!";

async fn index(_: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    Ok(Response::new(Full::new(Bytes::from(INDEX))))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let test_sockets = vec!(
        SocketAddr::from_str("127.0.0.1:8080").unwrap(),
        SocketAddr::from_str("127.0.0.1:8081").unwrap()
    );
    let test_sockets2 = vec!(
        SocketAddr::from_str("127.0.0.1:8443").unwrap(),
        SocketAddr::from_str("127.0.0.1:8444").unwrap()
    );
    // Get path of TLS certs
    let (private_key_path, cert_chain_path) = get_path();
    let server_config = Arc::new(tls::get_server_config(cert_chain_path, private_key_path));
    let (http_sockets, mut http_listeners) = bind_sockets(test_sockets).await;
    let (https_sockets, mut https_listeners) = bind_sockets(test_sockets2).await;
    // Launch listeners
    let mut http_listener_set = JoinSet::new();
    while let Some(listener) = http_listeners.pop() {
        http_listener_set.spawn(listen_http(listener));
    }
    let mut https_listener_set = JoinSet::new();
    let https_cancel_token = CancellationToken::new();
    while let Some(listener) = https_listeners.pop() {
        https_listener_set.spawn(listen_https(listener, server_config.clone(), https_cancel_token.child_token()));
    }
    let daemon = async move {
        for socket in &http_sockets {
            println!("Listening on socket: {}", socket);
        }
        let mut counter: usize = 0;
        let pause_at: usize = 10;
        let run_until: usize = 60;
        while counter < run_until {
            tokio::time::sleep(Duration::from_millis(1000)).await;
            if counter == pause_at {
                https_cancel_token.cancel();
                let mut https_listeners = Vec::new();
                while let Some(result) = https_listener_set.join_next().await {
                    let result = result.unwrap();
                    println!("Was listening on {}", result.local_addr().unwrap());
                    https_listeners.push(result);
                }
                let (private_key_path, cert_chain_path) = get_path();
                let server_config = Arc::new(tls::get_server_config(cert_chain_path, private_key_path));
                let https_cancel_token = CancellationToken::new();
                while let Some(listener) = https_listeners.pop() {
                    https_listener_set.spawn(listen_https(listener, server_config.clone(), https_cancel_token.child_token()));
                }
            }
            counter += 1;
            println!("Time elapsed: {} second/s.", counter);
        }
        http_listener_set.shutdown().await;
        https_listener_set.shutdown().await;
        for listener in https_listeners {
            https_listener_set.spawn(listen_https(listener, server_config.clone(), https_cancel_token.child_token()));
        }
    };
    daemon.await;
    Ok(())
}

async fn bind_sockets(sockets: Vec<SocketAddr>) -> (Vec<SocketAddr>, Vec<TcpListener>) {
    let mut bound_sockets = Vec::new();
    let mut listeners = Vec::new();
    for socket in sockets {
        match TcpListener::bind(&socket).await {
            Ok(l) => {
                bound_sockets.push(socket);
                listeners.push(l);
            },
            Err(e) => eprintln!("Error binding socket!: {}", e)
        };
    }
    (bound_sockets, listeners)
}

async fn listen_http(listener: TcpListener) -> TcpListener {
    println!("Listening on http://{}!", listener.local_addr().unwrap());
    loop {
        let (stream, addr) = listener.accept().await.unwrap();
        let io = TokioIo::new(stream);
        println!("HTTP request received from {}!", addr);
        tokio::task::spawn(async move {
            if let Err(err) = auto::Builder::new(TokioExecutor::new())
                .serve_connection(io, service_fn(index))
                .await
            {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
}

fn get_path() -> (PathBuf, PathBuf) {
    print!("Enter the directory paths of the certificates: ");
    io::stdout().flush().unwrap();
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer).unwrap();
    let directory = PathBuf::from(buffer.trim_end());
    let private_key = directory.clone().join("privkey.pem");
    let cert_chain = directory.join("fullchain.pem");
    println!("Got paths: {} and {}", private_key.to_str().unwrap(), cert_chain.to_str().unwrap());
    (private_key, cert_chain)
}

async fn listen_https(listener: TcpListener, server_config: Arc<ServerConfig>, cancel_token: CancellationToken) -> TcpListener {
    println!("Listening on https://{}!", listener.local_addr().unwrap());
    // Build TLS configuration.
    let tls_acceptor = TlsAcceptor::from(server_config);
    loop {
        let (stream, addr) = select! {
            biased;
            _ = cancel_token.cancelled() => {
                // The token was cancelled
                return listener;
            }
            res = listener.accept() => {
                match res {
                    Ok((s, a)) => (s, a),
                    Err(e) => {
                        eprintln!("Bruh moment!: {}", e);
                        continue;
                    }
                }
            },
        };
        println!("HTTPS request received from {}!", addr);
        let tls_acceptor = tls_acceptor.clone();
        tokio::task::spawn(async move {
            let tls_stream = match tls_acceptor.accept(stream).await {
                Ok(tls_stream) => tls_stream,
                Err(err) => {
                    eprintln!("failed to perform tls handshake: {err:#}");
                    return;
                }
            };
            let io = TokioIo::new(tls_stream);
            if let Err(err) = auto::Builder::new(TokioExecutor::new())
                .serve_connection(io, service_fn(index))
                .await
            {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
}
