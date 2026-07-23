use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;
use std::collections::VecDeque;

/// Queue-backed smoltcp device that directly carries complete IP packets.
pub(crate) struct IpTunnelDevice {
    rx_queue: VecDeque<Vec<u8>>,
    tx_queue: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl IpTunnelDevice {
    pub(crate) fn new(mtu: usize) -> Self {
        Self {
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
            mtu,
        }
    }

    pub(crate) fn push_rx_packet(&mut self, packet: Vec<u8>) {
        self.rx_queue.push_back(packet);
    }

    pub(crate) fn pop_tx_packet(&mut self) -> Option<Vec<u8>> {
        self.tx_queue.pop_front()
    }
}

pub(crate) struct TunnelRxToken {
    packet: Vec<u8>,
}

impl phy::RxToken for TunnelRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet)
    }
}

pub(crate) struct TunnelTxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl phy::TxToken for TunnelTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        self.queue.push_back(packet);
        result
    }
}

impl Device for IpTunnelDevice {
    type RxToken<'a>
        = TunnelRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = TunnelTxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx_queue.pop_front()?;
        Some((
            TunnelRxToken { packet },
            TunnelTxToken {
                queue: &mut self.tx_queue,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TunnelTxToken {
            queue: &mut self.tx_queue,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.max_burst_size = Some(64);
        caps
    }
}
