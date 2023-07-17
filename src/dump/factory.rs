use std::{
    mem, thread,
    time::Duration,
};

use anyhow::{bail, Result};
use libc::timeval;
use log::error;
use pcap;

use crate::core::signals::Running;

pub(super) struct PacketEventsFactory {
    map: libbpf_rs::Map,
}

impl PacketEventsFactory {
    pub(super) fn new() -> Result<Self> {
        let opts = libbpf_sys::bpf_map_create_opts {
            sz: mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
            ..Default::default()
        };

        let map = libbpf_rs::Map::create(
            libbpf_rs::MapType::RingBuf,
            Some("packets_event_map"),
            0,
            0,
            4096 * 16, // 1500B packets * X entries.
            &opts,
        )
        .or_else(|e| bail!("Failed to create packets event map: {}", e))?;

        let run_state = Running::new();
        let run = run_state.clone();

        let capture = pcap::Capture::dead(pcap::Linktype(1) /* Ethernet */)?;
        let mut out = unsafe {
            capture.savefile_raw_fd(1 /* stdout */)?
        };

        let process_event = move |data: &[u8]| -> i32 {
            if !run.running() || data.len() != mem::size_of::<BpfPacketEvent>() {
                error!("Wrong event size");
                return -4;
            }

            let timestamp = u64::from_ne_bytes(data[..8].try_into().unwrap());
            let len = u32::from_ne_bytes(data[8..12].try_into().unwrap());
            let caplen = u32::from_ne_bytes(data[12..16].try_into().unwrap());

            let header = pcap::PacketHeader {
                ts: timeval {
                    tv_sec: (timestamp / 1000000000) as i64,
                    tv_usec: (timestamp / 1000) as i64,
                },
                caplen,
                len,
            };
            let packet = pcap::Packet {
                header: &header,
                data: &data[16..],
            };

            out.write(&packet);
            let _ = out.flush();
            0
        };

        let mut rb = libbpf_rs::RingBufferBuilder::new();
        rb.add(&map, process_event)?;
        let rb = rb.build()?;
        let run = run_state.clone();
        thread::spawn(move || {
            while run.running() {
                if let Err(e) = rb.poll(Duration::from_millis(200)) {
                    match e {
                        libbpf_rs::Error::System(4) => (),
                        _ => error!("Unexpected error while polling ({e})"),
                    }
                }
            }
        });

        Ok(Self { map })
    }

    pub(super) fn map_fd(&self) -> i32 {
        self.map.fd()
    }
}

#[repr(C, packed)]
pub(super) struct BpfPacketEvent {
    pub(super) timestamp: u64,
    pub(super) len: u32,
    pub(super) caplen: u32,
    pub(super) packet: [u8; 256],
}
