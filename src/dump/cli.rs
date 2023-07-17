use std::{thread, time::Duration};

use anyhow::{bail, Result};
use clap::Parser;
use log::info;

use super::{dump_hook, factory::PacketEventsFactory};
use crate::{
    cli::*,
    core::{
        filters::{packets::filter::FilterPacket, BpfFilter, Filter},
        inspect::check::collection_prerequisites,
        kernel::Symbol,
        probe::{self, Hook, Probe},
        signals::Running,
        tracking::skb_tracking::init_tracking,
    },
    module::Modules,
};

/// Dump packets in pcap format.
#[derive(Parser, Debug, Default)]
#[command(name = "dump")]
pub(crate) struct Dump {
    #[arg(
        id = "filter-packet",
        short,
        long,
        help = r#"Add a packet filter to all targets. The syntax follows the structure of p
cap-filer(7).

Example: --filter-packet "ip dst host 10.0.0.1""#
    )]
    pub(super) packet_filter: Option<String>,
    #[arg(
        help = "Add a probe on the given target. The probe should follow the
TYPE:TARGET pattern.

Valid TYPEs:
- kprobe: kernel probe.
- kretprobe: kernel return probe.
- tp: kernel tracepoint.

Example: --probe tp:skb:kfree_skb"
    )]
    pub(super) probe: String,
}

impl SubCommandParserRunner for Dump {
    fn run(&mut self, _: Modules) -> Result<()> {
        // Check if we can.
        collection_prerequisites()?;

        //crate::core::probe::common::set_ebpf_debug(true)?;

        let factory = PacketEventsFactory::new()?;
        let mut probes = probe::ProbeManager::new()?;

        let mut run = Running::new();
        run.register_term_signals()?;

        // Setup filters.
        if let Some(f) = &self.packet_filter {
            let fb = FilterPacket::from_string(f.to_string())?;
            probes.register_filter(Filter::Packet(BpfFilter(fb.to_bytes()?)))?;
        }

        // Register dump hook.
        probes.register_kernel_hook(Hook::from(dump_hook::DATA))?;

        // Intall the user defined probe.
        let (type_str, target) = match self.probe.split_once(':') {
            Some((type_str, target)) => (type_str, target),
            None => {
                info!(
                    "Invalid probe format, no TYPE given in '{}', using 'kprobe:{}'. See th
e help.",
                    self.probe, self.probe
                );
                ("kprobe", self.probe.as_str())
            }
        };
        let symbol = Symbol::from_name(target)?;
        probes.register_probe(match type_str {
            "kprobe" => Probe::kprobe(symbol)?,
            "kretprobe" => Probe::kretprobe(symbol)?,
            "tp" => Probe::raw_tracepoint(symbol)?,
            x => bail!("Invalid TYPE {}. See the help.", x),
        })?;

        // Reuse factory map in the hooks.
        probes.reuse_map("packets_event_map", factory.map_fd())?;

        // Setup tracking gc.
        let mut tracking_gc = init_tracking(&mut probes)?;
        tracking_gc.start(run.clone())?;

        // Start the collection.
        probes.attach()?;

        while run.running() {
            thread::sleep(Duration::from_secs(1));
        }

        Ok(())
    }
}
