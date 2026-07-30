use super::IpTunnelDevice;
use crate::core::{crypto, protocol};
use anyhow::{Context, Result};
use smoltcp::wire::{IpAddress, Ipv4Packet, TcpPacket};
use std::io::ErrorKind;
use std::net::{Ipv4Addr, UdpSocket};
use std::time::{Duration, Instant};

pub(crate) const VPN_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);

#[allow(clippy::too_many_arguments)]
pub(crate) fn receive_vpn(
    sock: &UdpSocket,
    device: &mut IpTunnelDevice,
    xor_key: &[u8],
    sid: u16,
    token: u32,
    mtu: usize,
    encryption: u8,
    session_started: Instant,
) -> Result<()> {
    let mut buf = vec![0u8; 65535];
    loop {
        match sock.recv(&mut buf) {
            Ok(n) if n >= 8 => {
                let packet_type = buf[0];
                let packet_sid = u16::from_be_bytes([buf[2], buf[3]]);
                let packet_token = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
                if packet_sid != sid || packet_token != token {
                    continue;
                }
                if packet_type == protocol::PT_CLOSE {
                    anyhow::bail!(
                        "VPN server closed the session after {:?}: len={n} enc={} sid={:#06x} \
                         token={:#010x} payload={}",
                        session_started.elapsed(),
                        buf[1],
                        packet_sid,
                        packet_token,
                        crypto::hex(&buf[8..n])
                    );
                }
                if packet_type == protocol::PT_PING_REQ {
                    let header = protocol::pkhdr(protocol::PT_PING_RSP, encryption, sid, token);
                    sock.send(&protocol::ctrl_pkt(&header, &[]))
                        .context("send VPN keepalive response")?;
                    continue;
                }
                if packet_type != protocol::PT_DATA && packet_type != protocol::PT_DATA_ENC {
                    continue;
                }
                let mut packet = buf[8..n].to_vec();
                if packet_type == protocol::PT_DATA_ENC {
                    crypto::xor(&mut packet, xor_key);
                }
                if validate_inner_ipv4(&packet, mtu) {
                    log_tcp_packet("VPN RX", &packet);
                    device.push_rx_packet(packet);
                }
            }
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(()),
            Err(e) => return Err(e).context("receive VPN packet"),
        }
    }
}

pub(crate) fn send_vpn_keepalive(
    sock: &UdpSocket,
    sid: u16,
    token: u32,
    encryption: u8,
    last_keepalive: &mut Instant,
) -> Result<()> {
    if last_keepalive.elapsed() < VPN_KEEPALIVE_INTERVAL {
        return Ok(());
    }
    // Send an empty data frame so the keepalive is associated with
    // the authenticated sid/token data session.
    let packet_type = if encryption == 0 {
        protocol::PT_DATA
    } else {
        protocol::PT_DATA_ENC
    };

    let header = protocol::pkhdr(packet_type, encryption, sid, token);
    sock.send(&protocol::data_pkt(&header, &[]))
        .context("send VPN session keepalive")?;

    *last_keepalive = Instant::now();
    Ok(())
}

pub(crate) fn send_vpn(
    sock: &UdpSocket,
    device: &mut IpTunnelDevice,
    xor_key: &[u8],
    sid: u16,
    token: u32,
    encryption: u8,
) -> Result<()> {
    while let Some(mut packet) = device.pop_tx_packet() {
        log_tcp_packet("VPN TX", &packet);
        let packet_type = if encryption == 0 {
            protocol::PT_DATA
        } else {
            crypto::xor(&mut packet, xor_key);
            protocol::PT_DATA_ENC
        };
        let header = protocol::pkhdr(packet_type, encryption, sid, token);
        sock.send(&protocol::data_pkt(&header, &packet))
            .context("send VPN packet")?;
    }
    Ok(())
}

fn validate_inner_ipv4(packet: &[u8], mtu: usize) -> bool {
    !packet.is_empty() && packet.len() <= mtu && packet[0] >> 4 == 4 && packet.len() >= 20
}

fn log_tcp_packet(direction: &str, packet: &[u8]) {
    if packet.len() < 40 || packet[0] >> 4 != 4 || packet[9] != 6 {
        return;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if ihl < 20 || packet.len() < ihl + 20 {
        return;
    }
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
    let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
    let flags = packet[ihl + 13];
    if flags & 0x07 == 0 {
        return;
    }

    let tcp_header_len = usize::from(packet[ihl + 12] >> 4) * 4;
    let options = if tcp_header_len >= 20 && packet.len() >= ihl + tcp_header_len {
        crypto::hex(&packet[ihl + 20..ihl + tcp_header_len])
    } else {
        "<invalid>".to_string()
    };
    let ip_ok = Ipv4Packet::new_unchecked(packet).verify_checksum();
    let tcp_ok = TcpPacket::new_unchecked(&packet[ihl..])
        .verify_checksum(&IpAddress::Ipv4(src), &IpAddress::Ipv4(dst));
    let seq = u32::from_be_bytes([
        packet[ihl + 4],
        packet[ihl + 5],
        packet[ihl + 6],
        packet[ihl + 7],
    ]);
    let ack = u32::from_be_bytes([
        packet[ihl + 8],
        packet[ihl + 9],
        packet[ihl + 10],
        packet[ihl + 11],
    ]);
    eprintln!(
        "[{direction}] {src}:{src_port} -> {dst}:{dst_port} flags={}{}{}{} len={} \
         seq={seq:#010x} ack={ack:#010x} checksum=ip:{ip_ok}/tcp:{tcp_ok} \
         tcp_hlen={tcp_header_len} options={options} raw={}",
        if flags & 0x02 != 0 { "S" } else { "" },
        if flags & 0x10 != 0 { "A" } else { "" },
        if flags & 0x04 != 0 { "R" } else { "" },
        if flags & 0x01 != 0 { "F" } else { "" },
        packet.len(),
        crypto::hex(packet)
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_ipv4_packets_within_mtu() {
        let mut ipv4 = vec![0; 20];
        ipv4[0] = 0x45;
        assert!(validate_inner_ipv4(&ipv4, 1380));
        assert!(!validate_inner_ipv4(&ipv4, 19));

        let mut ipv6 = vec![0; 40];
        ipv6[0] = 0x60;
        assert!(!validate_inner_ipv4(&ipv6, 1380));
        assert!(!validate_inner_ipv4(&[0x10; 20], 1380));
    }
}
