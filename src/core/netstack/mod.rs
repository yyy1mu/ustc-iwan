pub(crate) mod device;
pub(crate) mod dns;
pub(crate) mod tunnel;

pub(crate) use device::IpTunnelDevice;
pub(crate) use dns::{spawn_ipv4_query, DnsResult, DNS_SERVER};
pub(crate) use tunnel::{receive_vpn, send_vpn, send_vpn_keepalive, VPN_KEEPALIVE_INTERVAL};
