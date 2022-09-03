use std::{
    error::Error,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use log::{error, info};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::mpsc,
    time::timeout,
};

use crate::{
    context::{ConnectionContext, QueryContext, ServerContext},
    message::{Message, PacketType, ResponseCode},
    resolver,
    wire::{from_wire, to_wire},
};

pub struct UdpDnsServer {
    context: Arc<ServerContext>,
}

impl UdpDnsServer {
    pub fn new(context: Arc<ServerContext>) -> Self {
        Self { context }
    }

    pub async fn run(self) -> Result<(), Box<dyn Error>> {
        let socket = Arc::new(UdpSocket::bind(self.context.config.server.udp_bind_addr).await?);
        info!(
            "Listening for UDP on {}",
            self.context.config.server.udp_bind_addr,
        );

        let (tx, mut rx) = mpsc::channel::<([u8; 512], usize, SocketAddr)>(1024);

        let s = Arc::clone(&socket);
        tokio::spawn(async move {
            while let Some((packet, len, addr)) = rx.recv().await {
                let mut payload_size = 512;

                let mut response = match from_wire::<Message>(&packet[..len]) {
                    Ok(message) => {
                        payload_size = message.udp_payload_size() as usize;
                        resolver::resolve(
                            &message,
                            &mut QueryContext::new(Arc::new(Mutex::new(ConnectionContext::new(
                                Arc::clone(&self.context),
                                addr,
                                Duration::ZERO,
                            )))),
                        )
                        .await
                    }
                    Err(err) => {
                        error!("Error decoding packet: {}", err);

                        let mut response = Message::new(u16::from_be_bytes([packet[0], packet[1]]));
                        response
                            .set_packet_type(PacketType::Response)
                            .set_response_code(ResponseCode::FormatError);
                        response
                    }
                };

                response.truncate_to(
                    payload_size.min(self.context.config.server.udp_max_payload_size as usize),
                );

                let wire = match to_wire(&response) {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        error!("Error encoding packet: {}", err);

                        let mut response = Message::new(u16::from_be_bytes([packet[0], packet[1]]));
                        response
                            .set_packet_type(PacketType::Response)
                            .set_response_code(ResponseCode::ServerFailure);

                        to_wire(&response).unwrap()
                    }
                };

                _ = s.send_to(&wire, addr).await;
            }
        });

        loop {
            let mut buf = [0; 512];
            let (len, addr) = socket.recv_from(&mut buf).await?;

            tx.send((buf, len, addr)).await.unwrap();
        }
    }
}

pub struct TcpDnsServer {
    context: Arc<ServerContext>,
}

impl TcpDnsServer {
    pub fn new(context: Arc<ServerContext>) -> Self {
        Self { context }
    }

    pub async fn run(self) -> Result<(), Box<dyn Error>> {
        let listener = TcpListener::bind(self.context.config.server.tcp_bind_addr).await?;
        info!(
            "Listening for TCP on {}",
            self.context.config.server.tcp_bind_addr,
        );

        loop {
            let (mut stream, addr) = listener.accept().await?;
            let context = Arc::clone(&self.context);

            tokio::spawn(async move {
                let conn_context = Arc::new(Mutex::new(ConnectionContext::new(
                    Arc::clone(&context),
                    addr,
                    Duration::from_secs(300),
                )));

                loop {
                    let keepalive = conn_context.lock().unwrap().keepalive;
                    let size = match timeout(keepalive, stream.read_u16()).await {
                        Ok(Ok(size)) => size,
                        _ => return,
                    };

                    let mut packet = vec![0u8; size as usize];
                    if stream.read_exact(&mut packet).await.is_err() {
                        return;
                    };

                    let response = match from_wire::<Message>(&packet[..]) {
                        Ok(message) => {
                            resolver::resolve(
                                &message,
                                &mut QueryContext::new(Arc::clone(&conn_context)),
                            )
                            .await
                        }
                        Err(err) => {
                            error!("Error decoding packet: {}", err);

                            let mut response =
                                Message::new(u16::from_be_bytes([packet[0], packet[1]]));
                            response
                                .set_packet_type(PacketType::Response)
                                .set_response_code(ResponseCode::FormatError);
                            response
                        }
                    };

                    let wire = match to_wire(&response) {
                        Ok(bytes) => bytes,
                        Err(err) => {
                            error!("Error encoding packet: {}", err);

                            let mut response =
                                Message::new(u16::from_be_bytes([packet[0], packet[1]]));
                            response
                                .set_packet_type(PacketType::Response)
                                .set_response_code(ResponseCode::ServerFailure);

                            to_wire(&response).unwrap()
                        }
                    };

                    if stream.write_u16(wire.len() as u16).await.is_err() {
                        return;
                    };
                    if stream.write_all(&wire).await.is_err() {
                        return;
                    };
                }
            });
        }
    }
}
