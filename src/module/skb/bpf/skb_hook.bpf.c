#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include <common.h>

#define BIT(x) (1 << (x))

#define ETH_P_IP	0x0800
#define ETH_P_ARP	0x0806
#define ETH_P_IPV6	0x86dd

/* Skb raw event sections.
 *
 * Please keep in sync with its Rust counterpart in module::skb::bpf.
 */
#define COLLECT_DEV		7
#define COLLECT_NS		8
#define COLLECT_META		9
#define COLLECT_DATA_REF	10
#define COLLECT_PACKET		11
#define COLLECT_GSO		12

/* Skb hook configuration. A map is used to set the config from userspace.
 *
 * Please keep in sync with its Rust counterpart in module::skb::bpf.
 */
struct skb_config {
	u64 sections;
} __attribute__((packed));
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct skb_config);
} skb_config_map SEC(".maps");

/* Please keep the following structs in sync with its Rust counterpart in
 * module::skb::bpf.
 */
struct skb_netdev_event {
#define IFNAMSIZ	16
	u8 dev_name[IFNAMSIZ];
	u32 ifindex;
	u32 iif;
} __attribute__((packed));
struct skb_netns_event {
	u32 netns;
} __attribute__((packed));
struct skb_meta_event {
	u32 len;
	u32 data_len;
	u32 hash;
	u8 ip_summed;
	u32 csum;
	u8 csum_level;
	u32 priority;
} __attribute__((packed));
struct skb_data_ref_event {
	u8 nohdr;
	u8 cloned;
	u8 fclone;
	u8 users;
	u8 dataref;
} __attribute__((packed));
struct skb_gso_event {
	u8 flags;
	u8 nr_frags;
	u32 gso_size;
	u32 gso_segs;
	u32 gso_type;
} __attribute__((packed));
/* Please keep the following structs in sync with its Rust counterpart in
 * module::skb::event.
 */
struct skb_packet_event {
	u32 len;
	u32 capture_len;
#define PACKET_CAPTURE_SIZE	255
	u8 packet[PACKET_CAPTURE_SIZE];
} __attribute__((packed));

static __always_inline int process_packet(struct retis_raw_event *event,
					  struct sk_buff *skb)
{
	/* Use int instead of the underlying (smaller) unsigned type to allow
	 * signed arithmetic operations.
	 */
	int mac, headroom, linear_len;
	struct skb_packet_event *e;
	unsigned char *head;
	u16 network;
	u32 len;

	head = BPF_CORE_READ(skb, head);
	headroom = BPF_CORE_READ(skb, data) - head;

	mac = BPF_CORE_READ(skb, mac_header);
	network = BPF_CORE_READ(skb, network_header);
	len = BPF_CORE_READ(skb, len);
	linear_len = len - BPF_CORE_READ(skb, data_len); /* Linear buffer size */

	/* No data in the linear len, nothing to report */
	if (!linear_len)
		return 0;

	/* Best case: mac offset is set and valid */
	if (is_mac_data_valid(skb)) {
		long mac_offset, size;

		mac_offset = mac - headroom;
		size = MIN(linear_len - mac_offset, PACKET_CAPTURE_SIZE);
		if (size <= 0)
			return 0;

		e = get_event_section(event, COLLECTOR_SKB, COLLECT_PACKET,
				      sizeof(*e));
		if (!e)
			return 0;

		e->len = len - mac_offset;
		e->capture_len = size;
		bpf_probe_read_kernel(e->packet, size, head + mac);
	/* Valid network offset with an unset or invalid mac offset: we can fake
	 * the eth header.
	 */
	} else if (is_network_data_valid(skb)) {
		u16 etype = BPF_CORE_READ(skb, protocol);
		long network_offset, size;
		struct ethhdr *eth;

		/* We do need the ethertype to be set at the skb level here,
		 * otherwise we can't guess what kind of packet this is.
		 */
		if (!etype)
			return 0;

		network_offset = network - headroom;
		size = MIN(linear_len - network_offset, PACKET_CAPTURE_SIZE);
		size -= sizeof(struct ethhdr);
		if (size <= 0)
			return 0;

		e = get_event_section(event, COLLECTOR_SKB, COLLECT_PACKET,
				      sizeof(*e));
		if (!e)
			return 0;

		/* Fake eth header */
		eth = (struct ethhdr *)e->packet;
		__builtin_memset(eth, 0, sizeof(*eth));
		eth->h_proto = etype;

		e->len = len - network_offset + sizeof(*eth);
		e->capture_len = size;
		bpf_probe_read_kernel(e->packet + sizeof(*eth), size,
				      head + network);
	/* Can't guess any useful packet offset */
	} else {
		return 0;
	}

	return 0;
}

/* Must be called with a valid skb pointer */
static __always_inline int process_skb(struct retis_raw_event *event,
				       struct sk_buff *skb)
{
	struct skb_shared_info *si;
	struct skb_config *cfg;
	struct net_device *dev;
	unsigned char *head;
	u32 key = 0;

	cfg = bpf_map_lookup_elem(&skb_config_map, &key);
	if (!cfg)
		return 0;

	dev = BPF_CORE_READ(skb, dev);
	head = BPF_CORE_READ(skb, head);

	if (cfg->sections & BIT(COLLECT_PACKET))
		process_packet(event, skb);

	if (cfg->sections & BIT(COLLECT_DEV) && dev) {
		int ifindex = BPF_CORE_READ(dev, ifindex);

		if (ifindex > 0) {
			struct skb_netdev_event *e =
				get_event_section(event, COLLECTOR_SKB,
						  COLLECT_DEV, sizeof(*e));
			if (!e)
				return 0;

			bpf_probe_read(e->dev_name, IFNAMSIZ, dev->name);
			e->ifindex = ifindex;
			e->iif = BPF_CORE_READ(skb, skb_iif);
		}
	}

	if (cfg->sections & BIT(COLLECT_NS)) {
		struct skb_netns_event *e;
		u32 netns;

		/* If the network device is initialized in the skb, use it to
		 * get the network namespace; otherwise try getting the network
		 * namespace from the skb associated socket.
		 */
		if (dev) {
			netns = BPF_CORE_READ(dev, nd_net.net, ns.inum);
		} else {
			struct sock *sk = BPF_CORE_READ(skb, sk);

			if (!sk)
				goto skip_netns;

			netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
		}

		e = get_event_section(event, COLLECTOR_SKB, COLLECT_NS, sizeof(*e));
		if (!e)
			return 0;

		e->netns = netns;
	}

skip_netns:
	if (cfg->sections & BIT(COLLECT_META)) {
		struct skb_meta_event *e =
			get_event_section(event, COLLECTOR_SKB,
					  COLLECT_META, sizeof(*e));
		if (!e)
			return 0;

		e->len = BPF_CORE_READ(skb, len);
		e->data_len = BPF_CORE_READ(skb, data_len);
		e->hash = BPF_CORE_READ(skb, hash);
		e->ip_summed = (u8)BPF_CORE_READ_BITFIELD_PROBED(skb, ip_summed);
		e->csum = BPF_CORE_READ(skb, csum);
		e->csum_level = (u8)BPF_CORE_READ_BITFIELD_PROBED(skb, csum_level);
		e->priority = BPF_CORE_READ(skb, priority);
	}

	if (cfg->sections & BIT(COLLECT_DATA_REF)) {
		struct skb_data_ref_event *e =
			get_event_section(event, COLLECTOR_SKB,
					  COLLECT_DATA_REF, sizeof(*e));
		if (!e)
			return 0;

		e->nohdr = (u8)BPF_CORE_READ_BITFIELD_PROBED(skb, nohdr);
		e->cloned = (u8)BPF_CORE_READ_BITFIELD_PROBED(skb, cloned);
		e->fclone = (u8)BPF_CORE_READ_BITFIELD_PROBED(skb, fclone);
		e->users = (u8)BPF_CORE_READ(skb, users.refs.counter);

		si = (struct skb_shared_info *)(BPF_CORE_READ(skb, end) + head);
		e->dataref = (u8)BPF_CORE_READ(si, dataref.counter);
	}

	if (cfg->sections & BIT(COLLECT_GSO)) {
		struct skb_shared_info *shinfo;
		struct skb_gso_event *e;

		/* See skb_shinfo */
		shinfo = (void *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, end));
		/* See skb_is_gso */
		if (!BPF_CORE_READ(shinfo, gso_size))
			goto skip_gso;

		e = get_event_section(event, COLLECTOR_SKB, COLLECT_GSO,
				      sizeof(*e));
		if (!e)
			return 0;

		e->flags = bpf_core_field_exists(shinfo->flags) ?
			   BPF_CORE_READ(shinfo, flags) : 0;
		e->nr_frags = BPF_CORE_READ(shinfo, nr_frags);
		e->gso_size = BPF_CORE_READ(shinfo, gso_size);
		e->gso_segs = BPF_CORE_READ(shinfo, gso_segs);
		e->gso_type = BPF_CORE_READ(shinfo, gso_type);
	}

skip_gso:
	return 0;
}

DEFINE_HOOK(F_AND, RETIS_ALL_FILTERS,
	struct sk_buff *skb;

	skb = retis_get_sk_buff(ctx);
	if (skb)
		process_skb(event, skb);

	return 0;
)

char __license[] SEC("license") = "GPL";
