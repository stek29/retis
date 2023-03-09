#include <openvswitch.h>
#include <bpf/bpf_core_read.h>

#include <common.h>
#include "ovs_common.h"

/* Please keep in sync with its Rust counterpart in crate::module::ovs::bpf.rs. */
struct upcall_event {
	u8 cmd;
	u32 port;
	u32 cpu;
} __attribute__((packed));

/* Hook for raw_tracepoint:openvswitch:ovs_dp_upcall. */
DEFINE_HOOK(
	struct dp_upcall_info *upcall;
	struct upcall_context uctx = {};
	struct upcall_event *upcall_event;
	u64 tid = bpf_get_current_pid_tgid();

	upcall = (struct dp_upcall_info *) ctx->regs.reg[3];
	if (!upcall)
		return 0;

	upcall_event = get_event_section(event, COLLECTOR_OVS, OVS_DP_UPCALL,
				         sizeof(*upcall_event));
	if (!upcall_event)
		return 0;

	upcall_event->port = BPF_CORE_READ(upcall, portid);
	upcall_event->cmd = BPF_CORE_READ(upcall, cmd);
	upcall_event->cpu = bpf_get_smp_processor_id();

	/* Insert upcall context in the map so it can be read by upcall queue
	 * events. */
	uctx.ts = ctx->timestamp;
	uctx.cpu = upcall_event->cpu;

	if (!bpf_map_update_elem(&inflight_upcalls, &tid, &uctx, BPF_ANY)) {
		return -1;
	}

	return 0;
)

char __license[] SEC("license") = "GPL";