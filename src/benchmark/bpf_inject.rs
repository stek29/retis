use std::{
    fs::{File, OpenOptions},
    io::Write,
    mem,
    os::fd::AsRawFd,
    sync::{Arc, Barrier},
    thread,
    time::{Duration, Instant},
};

use anyhow::{bail, Result};
use libc;
use nix::{
    ioctl_read_bad, ioctl_write_ptr_bad, request_code_write,
    sys::socket::{self, *},
};

use super::events::BenchmarkEvent;
use crate::{
    cli,
    core::{
        events::{bpf::BpfEventsFactory, EventFactory, EventResult},
        filters::{packets::filter::FilterPacket, BpfFilter, Filter},
        kernel::Symbol,
        probe::{self, Probe},
        signals::Running,
        tracking::skb_tracking::init_tracking,
    },
    module::{get_modules, ModuleId},
};

pub(super) fn bench() -> Result<()> {
    // Setup the TAP interface.
    let tap = setup_tap()?;

    // Setup the core API.
    let mut run = Running::new();
    let mut modules = get_modules()?;
    let mut factory = BpfEventsFactory::new(4)?;
    let mut probes = probe::ProbeManager::new()?;

    // Init the cli.
    let mut cli = cli::get_cli()?.build_from(vec![
        "retis",
        "collect",
        "-c",
        "skb,skb-tracking",
        "--skb-sections",
        "all",
    ])?;
    let cmd = cli.get_subcommand_mut()?.dynamic_mut().unwrap();
    modules
        .collectors()
        .iter()
        .try_for_each(|(_, c)| c.register_cli(cmd))?;
    let cli = cli.run()?;

    // Initialize the collectors.
    for collector in [ModuleId::Skb, ModuleId::SkbTracking] {
        let c = modules.get_collector(&collector).unwrap();
        c.init(&cli, &mut probes)?;
    }

    // Initialize tracking.
    let (mut tracking_gc, _gc_map) = init_tracking(&mut probes)?;
    tracking_gc.start(run.clone())?;

    // Setup factory.
    factory
        .maps_fd()
        .iter()
        .try_for_each(|(name, fd)| probes.reuse_map(name, *fd))?;
    factory.start(|| modules.section_factories().unwrap())?;

    // Set a filter.
    let fb = FilterPacket::from_string("icmp and ip src 127.0.0.1".to_string())?;
    probes.register_filter(Filter::Packet(BpfFilter(fb.to_bytes()?)))?;

    // Set probes.
    let symbol = Symbol::from_name("net:netif_receive_skb")?;
    probes.register_probe(Probe::raw_tracepoint(symbol)?)?;

    // Start collecting.
    probes.attach()?;
    for collector in [ModuleId::Skb, ModuleId::SkbTracking] {
        let c = modules.get_collector(&collector).unwrap();
        c.start()?;
    }

    // Use a barrier to sync threads start.
    let barrier = Arc::new(Barrier::new(2));
    let t_barrier = Arc::clone(&barrier);

    // Start packet generation thread.
    let mut trun = run.clone();
    thread::spawn(move || {
        // Wait for the collection loop to start.
        t_barrier.wait();

        generate_traffic(tap).unwrap();

        // Wait for the collection loop to process all events.
        thread::sleep(Duration::from_secs(1));
        trun.terminate();
    });

    // Collect events.
    let mut time_spent = 0;
    let mut events = 0;
    barrier.wait();

    let now = Instant::now();

    while run.running() {
        use EventResult::*;
        if let Ok(event) = factory.next_event(Some(Duration::from_secs(1))) {
            match event {
                Event(event) => {
                    let section = event
                        .get_section::<BenchmarkEvent>(ModuleId::Benchmark)
                        .unwrap();

                    time_spent += section.probe_end - section.probe_start;
                    events += 1;
                    if events == 1000000 {
                        println!("1M_events_reported_us {}", now.elapsed().as_micros());
                    }
                }
                Eof => break,
                Timeout => continue,
            }
        }
    }

    // Stop threads & cleanup
    run.terminate();
    probes.detach()?;
    probes.report_counters()?;
    for collector in [ModuleId::Skb, ModuleId::SkbTracking] {
        let c = modules.get_collector(&collector).unwrap();
        c.stop()?;
    }
    tracking_gc.join()?;
    factory.stop()?;

    // Print results
    println!("events {events}");
    println!("time_in_probe_us {}", time_spent / 1000);

    Ok(())
}

fn generate_traffic(mut tap: File) -> Result<()> {
    // Ping 127.0.0.1.
    let packet = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45,
        0x00, 0x00, 0x54, 0x86, 0x15, 0x40, 0x00, 0x40, 0x01, 0xb6, 0x91, 0x7f, 0x00, 0x00, 0x01,
        0x7f, 0x00, 0x00, 0x01, 0x08, 0x00, 0xa9, 0x74, 0x00, 0x03, 0x00, 0x01, 0x1a, 0x75, 0xd2,
        0x64, 0x00, 0x00, 0x00, 0x00, 0x9e, 0xda, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11,
        0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    ];

    for _ in 0..1000000 {
        tap.write_all(&packet)?;
    }

    Ok(())
}

const TUNSETIFF: u8 = 202;
ioctl_write_ptr_bad!(
    ioctl_tunsetiff,
    request_code_write!('T', TUNSETIFF, mem::size_of::<libc::c_int>()),
    libc::ifreq
);

ioctl_read_bad!(ioctl_gifflags, libc::SIOCGIFFLAGS, libc::ifreq);
ioctl_write_ptr_bad!(ioctl_sifflags, libc::SIOCSIFFLAGS, libc::ifreq);

fn setup_tap() -> Result<File> {
    let tun = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")?;
    let tun_fd = tun.as_raw_fd();

    let mut iface_name = "tap-retis".chars().map(|c| c as i8).collect::<Vec<i8>>();
    iface_name.resize(16, 0);
    let flags = libc::IFF_TAP | libc::IFF_NO_PI;
    let mut ifr = libc::ifreq {
        ifr_name: iface_name.try_into().unwrap(),
        ifr_ifru: libc::__c_anonymous_ifr_ifru {
            ifru_flags: flags as i16,
        },
    };

    if let Err(e) = unsafe { ioctl_tunsetiff(tun_fd, &ifr) } {
        bail!("Could not create TAP device: error {e}");
    }

    let socket = socket(
        socket::AddressFamily::Inet,
        socket::SockType::Datagram,
        socket::SockFlag::empty(),
        socket::SockProtocol::NetlinkRoute,
    )?;

    if let Err(e) = unsafe { ioctl_gifflags(socket, &mut ifr) } {
        bail!("Could not get TAP device flags: error {e}");
    }

    let flags = unsafe { ifr.ifr_ifru.ifru_flags };
    ifr.ifr_ifru.ifru_flags = flags | libc::IFF_UP as i16;
    if let Err(e) = unsafe { ioctl_sifflags(socket, &ifr) } {
        bail!("Could not set TAP device up: error {e}");
    }

    Ok(tun)
}
