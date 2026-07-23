use crate::cli;
use anyhow::{Context, Result};
use iwan::core::{auth, crypto, socks};
use std::time::Duration;

pub fn run(args: &cli::SocksArgs) -> Result<()> {
    let ct = auth::get_ct(&args.user, &args.pass, &args.ct_pass);
    let nonce = auth::rand_u32()?;
    let open = auth::build_open(&args.user, &ct, args.mtu, args.encrypt, nonce);
    let sock = auth::udp_connect(&args.server, args.port, 3000)?;

    let authenticated = {
        let mut result = None;
        for i in 0u32..=3 {
            sock.send(&open).context("send OPEN")?;
            println!("[{i}] -> OPEN");
            let mut buf = [0u8; 4096];
            match sock.recv(&mut buf) {
                Ok(n) => match auth::parse_ack(&buf[..n], nonce) {
                    Ok(value) => {
                        result = Some(value);
                        break;
                    }
                    Err(e) => eprintln!("[{i}] invalid reply: {e}"),
                },
                Err(e) => eprintln!("[{i}] timeout: {e}"),
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        result.context("auth failed")?
    };

    let inner_ip = authenticated
        .tun
        .parse()
        .context("server returned invalid tunnel IPv4 address")?;
    let gateway = authenticated
        .gw
        .parse()
        .context("server returned invalid gateway IPv4 address")?;
    let key = crypto::session_key(&args.user, &args.pass);
    let mtu = usize::from(authenticated.mtu.min(args.mtu));

    socks::run(
        &sock,
        socks::SocksConfig {
            listen: args.listen,
            inner_ip,
            gateway,
            mtu,
            xor_key: &key[..8],
            sid: authenticated.sid,
            token: authenticated.tok,
            encryption: args.encrypt,
        },
    )
}
