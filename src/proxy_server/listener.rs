use crate::proxy_server::errors::ListenerError;
use crate::proxy_server::server_traits::ServerTrait;
use crate::proxy_server::Config;
use async_trait::async_trait;
use std::net::SocketAddr;
use std::str::FromStr;
use tokio::net::TcpListener;

pub struct Listener {
    listener: TcpListener,
    proxies: Vec<SocketAddr>,
}

#[async_trait]
impl ServerTrait for Listener {
    async fn new(cnf: &Config) -> Self {
        let addr: SocketAddr = format!("0.0.0.0:{}", cnf.port).parse().unwrap();
        let listener = TcpListener::bind(addr).await.unwrap();
        let mut proxies = cnf
            .proxies
            .iter()
            .map(|p| SocketAddr::from_str(p.as_str()).unwrap())
            .collect::<Vec<_>>();

        Self { listener, proxies }
    }

    async fn start(&mut self) -> Result<(), ListenerError> {
        loop {
            if let Ok((socket, address)) = self.listener.accept().await {
                tokio::spawn(async move {
                    log::info!("Client connected: {}", address);
                    let socket = socket
                });
            }
        }
    }

    async fn stop(&self) {
        todo!()
    }

    async fn reload(&self) {
        todo!()
    }
}
