#ifndef __RETIS_BENCHMARK__
#define __RETIS_BENCHMARK__

#ifdef RETIS_ENABLE_BENCHMARK

struct benchmark_event {
	u64 probe_start;
	u64 probe_end;
} __attribute__((packed));

static __always_inline int fill_benchmark_event(struct retis_raw_event *event,
						struct retis_context *ctx)
{
	struct benchmark_event *bench;

	/* Do not make the other sections available */
	event->size = 0;

	bench = get_event_section(event, COLLECTOR_BENCHMARK, 1, sizeof(*bench));
	if (!bench)
		return -1;

	bench->probe_start = ctx->timestamp;
	bench->probe_end = bpf_ktime_get_ns();

	return 0;
}

/* Force all events to be reported */
#define get_event_size(event) 1

#else /* RETIS_ENABLE_BENCHMARK */

static __always_inline int fill_benchmark_event(struct retis_raw_event *event,
						struct retis_context *ctx)
{
	return 0;
}

#endif /* RETIS_ENABLE_BENCHMARK */

#endif /* __RETIS_BENCHMARK__ */
