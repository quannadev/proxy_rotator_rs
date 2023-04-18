#[derive(Clone, Debug)]
pub enum ListenerError {
    RunError(String),
}

#[derive(Clone, Debug)]
pub enum SocksErrors {
    Connect(String),
    Invalid(String),
    Unknown(String),
}
