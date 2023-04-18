#[derive(Clone, Debug)]
pub struct Config {
    pub port: i32,
    pub proxies: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: 1337,
            proxies: Vec::new(),
        }
    }
}
