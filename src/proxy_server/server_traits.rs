use crate::proxy_server::errors::ListenerError;
use crate::proxy_server::Config;
use async_trait::async_trait;

#[async_trait]
pub trait ServerTrait {
    async fn new(cnf: &Config) -> Self;
    async fn start(&mut self) -> Result<(), ListenerError>;
    async fn stop(&self);
    async fn reload(&self);
}
