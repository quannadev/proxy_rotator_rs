use proxy_rotater::{Config, Listener, ServerTrait};

#[tokio::main]
async fn main() {
    env_logger::init();
    let cnf = Config::default();
    let mut server = Listener::new(&cnf).await;
    server.start().await.unwrap()
}
