use std::fmt;

use anyhow::Result;

use crate::{
    core::events::{
        bpf::{parse_single_raw_section, BpfRawSection},
        *,
    },
    event_section, event_section_factory,
    module::ModuleId,
};

#[derive(Clone, Copy, PartialEq)]
#[event_section]
#[repr(C)]
pub(crate) struct BenchmarkEvent {
    pub(super) probe_start: u64,
    pub(super) probe_end: u64,
}

impl EventFmt for BenchmarkEvent {
    fn event_fmt(&self, _: &mut fmt::Formatter, _: DisplayFormat) -> fmt::Result {
        Ok(())
    }
}

#[derive(Default)]
#[event_section_factory(BenchmarkEvent)]
pub(crate) struct BenchmarkEventFactory {}

impl RawEventSectionFactory for BenchmarkEventFactory {
    fn from_raw(&mut self, raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
        let event = parse_single_raw_section::<BenchmarkEvent>(ModuleId::Benchmark, &raw_sections)?;
        Ok(Box::new(*event))
    }
}
