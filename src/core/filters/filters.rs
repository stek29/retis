/// eBPF filter wrapper containing the sequence of bytes composing the eBPF program
use std::{collections::HashMap, sync::Mutex};

use anyhow::Result;
use once_cell::sync::Lazy;

use crate::core::workaround;

#[derive(Clone)]
pub(crate) struct BpfFilter(pub(crate) Vec<u8>);

#[derive(Clone)]
pub(crate) enum Filter {
    Packet(BpfFilter),
}

static FM: Lazy<Mutex<HashMap<u32, Filter>>> = Lazy::new(|| Mutex::new(HashMap::new()));

pub(crate) fn register_filter(r#type: u32, filter: &Filter) -> Result<()> {
    FM.lock().unwrap().insert(r#type, filter.clone());
    Ok(())
}

pub(crate) fn get_filter(r#type: u32) -> Option<Filter> {
    FM.lock().unwrap().get(&r#type).cloned()
}

pub(crate) fn register_filter_handler(
    sec: &str,
    prog_type: libbpf_rs::ProgramType,
    func: libbpf_sys::libbpf_prog_prepare_load_fn_t,
) -> Result<()> {
    let opts = workaround::ProgHandlerOpts {
        prepare_load_fn: func,
        cookie: 0xdeadbeef,
        ..Default::default()
    };
    workaround::register_prog_handler(
        Some(sec.to_string()),
        prog_type,
        libbpf_rs::ProgramAttachType::CgroupInetIngress,
        opts,
    )?;

    Ok(())
}
