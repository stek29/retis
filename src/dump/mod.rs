//! # Dump
//!
//! Dumps packets directly from an skb-aware function in the kernel and output
//! them in pcap format for later (or piped) processing by pcap-aware utilities.

pub(crate) mod cli;
mod factory;

mod dump_hook {
    include!("bpf/.out/dump.rs");
}
