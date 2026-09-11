use anyhow::{Context, Result};
use smoltcp::iface::{Config, Interface};
use smoltcp::time::Instant;
use smoltcp::wire::HardwareAddress;
use std::net::{TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant, SystemTime, UNIX_EPOCH};

use super::connections::Connections;
use super::ProxyConfig;
use crate::core::netstack::{
    receive_vpn, send_vpn, send_vpn_keepalive, IpTunnelDevice, VPN_KEEPALIVE_INTERVAL,
};
use crate::core::protocol;

const DEFAULT_POLL: Duration = Duration::from_millis(10);

/// The VPN session runtime: keeps the tunnel socket, the userspace device
/// and the session keys, and pumps packets between them and the server.
pub(super) struct Engine<'a> {
    sock: &'a UdpSocket,
    device: IpTunnelDevice,
    connections: Connections<'a>,
    xor_key: &'a [u8],
    sid: u16,
    token: u32,
    encryption: u8,
    mtu: usize,
    session_started: StdInstant,
    last_keepalive: StdInstant,
}

impl<'a> Engine<'a> {
    pub(super) fn new(
        listener: TcpListener,
        sock: &'a UdpSocket,
        config: &ProxyConfig<'a>,
    ) -> Result<Self> {
        let mut device = IpTunnelDevice::new(config.mtu);
        let mut iface_config = Config::new(HardwareAddress::Ip);
        iface_config.random_seed = random_seed();
        let iface = Interface::new(iface_config, &mut device, now());

        let session_started = StdInstant::now();
        let last_keepalive = session_started
            .checked_sub(VPN_KEEPALIVE_INTERVAL)
            .unwrap_or(session_started);

        Ok(Self {
            sock,
            device,
            connections: Connections::new(listener, iface, config)?,
            xor_key: config.xor_key,
            sid: config.sid,
            token: config.token,
            encryption: config.encryption,
            mtu: config.mtu,
            session_started,
            last_keepalive,
        })
    }

    pub(super) fn run(&mut self) -> Result<()> {
        let running = Arc::new(AtomicBool::new(true));
        let stop = running.clone();
        ctrlc::set_handler(move || stop.store(false, Ordering::Relaxed))
            .context("set SIGINT handler")?;

        while running.load(Ordering::Relaxed) {
            self.tick()?;
            let delay = self
                .connections
                .poll_delay(now())
                .unwrap_or(DEFAULT_POLL)
                .min(DEFAULT_POLL);
            std::thread::sleep(delay);
        }

        self.connections.abort_all();
        self.connections.poll(&mut self.device, now());
        self.send_to_server()?;
        let close = protocol::pkhdr(protocol::PT_CLOSE, self.encryption, self.sid, self.token);
        let _ = self.sock.send(&protocol::ctrl_pkt(&close, &[]));
        Ok(())
    }

    fn tick(&mut self) -> Result<()> {
        send_vpn_keepalive(
            self.sock,
            self.sid,
            self.token,
            self.encryption,
            &mut self.last_keepalive,
        )?;
        self.connections.accept()?;
        receive_vpn(
            self.sock,
            &mut self.device,
            self.xor_key,
            self.sid,
            self.token,
            self.mtu,
            self.encryption,
            self.session_started,
        )?;
        self.connections.service_inputs();
        self.connections.handle_dns();
        self.connections.poll(&mut self.device, now());
        self.connections.update_states();
        self.connections.service_outputs();
        self.send_to_server()?;
        self.connections.reap();
        Ok(())
    }

    fn send_to_server(&mut self) -> Result<()> {
        send_vpn(
            self.sock,
            &mut self.device,
            self.xor_key,
            self.sid,
            self.token,
            self.encryption,
        )
    }
}

fn now() -> Instant {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64;
    Instant::from_millis(millis)
}

fn random_seed() -> u64 {
    use rand::RngCore;
    rand::thread_rng().next_u64()
}
