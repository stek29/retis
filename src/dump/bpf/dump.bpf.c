#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include <common.h>

#define min(a, b) ((a) < (b) ? (a) : (b))

/* Please keep synced with its Rust counterpart. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096 * 16);
} packets_event_map SEC(".maps");

/* Please keep synced with its Rust counterpart. */
struct packet_event {
	u64 timestamp;
	u32 len;
	u32 caplen;
	u8 packet[256];
} __attribute__ ((packed));

__always_inline void process_skb(struct retis_context *ctx, struct sk_buff *skb)
{
	struct packet_event *event;
	unsigned char *head, *data;
	u16 etype, mac, network;
	int size, data_offset;
	u32 len, data_len;

	etype = BPF_CORE_READ(skb, protocol);
	if (!etype)
		return;

	mac = BPF_CORE_READ(skb, mac_header);
	network = BPF_CORE_READ(skb, network_header);
	data = BPF_CORE_READ(skb, data);
	head = BPF_CORE_READ(skb, head);

	/* Check that network offset is set */
	if (!network || network == (u16)~0U)
		return;

	data_offset = data - head;
	if (data_offset < 0) /* Keep the verifier happy */
		return;

	len = BPF_CORE_READ(skb, len);
	data_len = BPF_CORE_READ(skb, data_len);
	len -= data_len; /* Linear buffer size */

	event = bpf_ringbuf_reserve(&packets_event_map, sizeof(*event), 0);
	if (!event)
		return;

	event->timestamp = ctx->timestamp;

	/* mac header is unset; using network offset & fake eth header */
	if (mac == (u16)~0U || network == mac) {
		struct ethhdr *eth = (struct ethhdr *)event->packet;
		int network_offset;

		network_offset = network - data_offset;
		size = min(len - network_offset, 256);
		size -= sizeof(struct ethhdr);
		if (size <= 0) {
			bpf_ringbuf_discard(event, 0);
			return;
		}

		/* Fake eth header */
		__builtin_memset(eth, 0, sizeof(*eth));
		eth->h_proto = etype;

		event->len = len - network_offset + sizeof(*eth);
		event->caplen = size;
		bpf_probe_read_kernel(event->packet + sizeof(*eth), size,
				      head + network);
	/* Valid mac header */
	} else {
		int mac_offset;

		mac_offset = mac - data_offset;
		size = min(len - mac_offset, 256);
		if (size <= 0) {
			bpf_ringbuf_discard(event, 0);
			return;
		}

		event->len = len - mac_offset;
		event->caplen = size;
		bpf_probe_read_kernel(event->packet, size, head + mac);
	}

	bpf_ringbuf_submit(event, 0);
}

DEFINE_HOOK(F_AND, RETIS_F_PACKET_PASS,
	struct sk_buff *skb;

	skb = retis_get_sk_buff(ctx);
	if (!skb)
		return 0;

	process_skb(ctx, skb);
	return 0;
)

char __license[] SEC("license") = "GPL";
