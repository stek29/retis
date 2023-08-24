//! # FilterPacket
//!
//! Object for packet filtering it implements from_string() and
//! to_bytes(). While the latter is self explainatory, the second
//! takes as input a pcap-filter string that gets converted to a bpf
//! program using libpcap, the resulting output gets then converted to
//! ebpf and returned for being consumed.

use std::mem;

use anyhow::{bail, Result};
use pcap::{Capture, Linktype};

use crate::core::{
    bpf_sys,
    filters::{
        get_filter,
        packets::{
            cbpf::BpfProg,
            ebpf::{eBpfProg, BpfReg},
            ebpfinsn::{eBpfInsn, MovInfo},
        },
        Filter,
    },
};

// please keep in sync with FILTER_MAX_INSNS in
// src/core/probe/kernel/bpf/include/common.h
const FILTER_MAX_INSNS: usize = 4096;

#[derive(Clone)]
pub(crate) struct FilterPacket(eBpfProg);

impl FilterPacket {
    pub(crate) fn from_string(fstring: String) -> Result<Self> {
        let bpf_capture = Capture::dead(Linktype::ETHERNET)?;
        let program = bpf_capture.compile(fstring.as_str(), true)?;
        let insns = program.get_instructions();
        let filter = BpfProg::try_from(unsafe { mem::transmute::<_, &[u8]>(insns) })?;

        let ebpf_filter = eBpfProg::try_from(filter)?;
        if ebpf_filter.len() > FILTER_MAX_INSNS {
            bail!("Filter exceeds the maximum allowed size.");
        }

        Ok(FilterPacket(ebpf_filter))
    }

    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.0.to_bytes())
    }
}

pub(crate) unsafe extern "C" fn prepare_load(
    prog: *mut libbpf_sys::bpf_program,
    _opts: *mut libbpf_sys::bpf_prog_load_opts,
    cookie: ::std::os::raw::c_long,
) -> std::os::raw::c_int {
    let filter = get_filter(cookie as u32);

    let f = if let Some(f) = filter {
        match f {
            Filter::Packet(bf) => bf.0,
        }
    } else {
        let mut default_filter = eBpfProg::new();
        default_filter.add(eBpfInsn::mov32(MovInfo::Imm {
            dst: BpfReg::R0,
            imm: 0x40000_i32,
        }));
        default_filter.to_bytes()
    };

    let filter: &[libbpf_sys::bpf_insn] = unsafe {
        std::slice::from_raw_parts(
            f.as_slice().as_ptr() as *const libbpf_sys::bpf_insn,
            f.len() / std::mem::size_of::<libbpf_sys::bpf_insn>(),
        )
    };

    let (insns, insns_cnt) = unsafe {
        (
            libbpf_sys::bpf_program__insns(prog),
            libbpf_sys::bpf_program__insn_cnt(prog),
        )
    };

    let insns = unsafe { std::slice::from_raw_parts(insns, insns_cnt as usize) };
    let mut prog_ext = insns.to_vec().clone();
    let mut inject_pos = 0;

    for (pos, insn) in prog_ext.iter().enumerate() {
        if insn.code == (bpf_sys::BPF_JMP | bpf_sys::BPF_CALL) as u8 && insn.imm == cookie as i32 {
            inject_pos = pos;
            break;
        }
    }

    prog_ext.splice(
        inject_pos..inject_pos + filter.len(),
        filter.to_vec().iter().cloned(),
    );

    libbpf_sys::bpf_program__set_insns(
        prog,
        prog_ext.as_mut_slice().as_mut_ptr(),
        prog_ext.len() as u64,
    )
}
