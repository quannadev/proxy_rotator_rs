## Socks5 Rotate

### Run
```bash
RUST_LOG=info cargo run --package proxy_rotater --bin proxy_rotater
```


### Test
```bash
curl -vx socks5h://127.0.0.1:1337 https://icanhazip.com/
```