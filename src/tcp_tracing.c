// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Sartura
 * Based on minimal.c by Facebook */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <sys/types.h>

#include "tcp_tracing.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t stop;

static void sig_int(int signo)
{
	stop = 1;
}

static int tc_attach(
	const struct bpf_program *program,
	int ifindex,
	enum bpf_tc_attach_point attach_point)
{
	int progfd = bpf_program__fd(program);

	LIBBPF_OPTS(bpf_tc_hook, hook,
				.ifindex = ifindex,
				.attach_point = attach_point);

	LIBBPF_OPTS(bpf_tc_opts, opts,
				.prog_fd = progfd,
				.flags = BPF_TC_F_REPLACE);

	if (bpf_tc_attach(&hook, &opts) < 0)
	{
		return -1;
	}

	return 0;
}

void bump_counters(const struct bpf_map *tcp_stats)
{
	__u64 ingress = 0;
	__u64 egress = 0;
	__u64 rxmit = 0;

	const __u32 ingress_index = 0;
	bpf_map__lookup_elem(
		tcp_stats,
		&ingress_index,
		sizeof(ingress_index),
		&ingress,
		sizeof(ingress),
		0);

	const __u32 egress_index = 1;
	bpf_map__lookup_elem(
		tcp_stats,
		&egress_index,
		sizeof(egress_index),
		&egress,
		sizeof(egress),
		0);

	const __u32 rxmit_index = 2;
	bpf_map__lookup_elem(
		tcp_stats,
		&rxmit_index,
		sizeof(rxmit_index),
		&rxmit,
		sizeof(rxmit),
		0);

	printf("TCP ingress: %llu - egress: %llu - rxmit: %llu\n", ingress, egress, rxmit);
	fflush(stdout);
}

int main(int argc, char **argv)
{
	struct tcp_tracing_bpf *skel = NULL;
	struct bpf_program *kprobe = NULL;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open load and verify BPF application */
	skel = tcp_tracing_bpf__open_and_load();
	if (!skel)
	{
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Create tc clsact */
	LIBBPF_OPTS(bpf_tc_hook, tc_hook,
				.ifindex = if_nametoindex("eth0"),
				.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS);

	bpf_tc_hook_destroy(&tc_hook);

	if (bpf_tc_hook_create(&tc_hook) < 0)
	{
		fprintf(stderr, "TC hook create failed: %s!\n", strerror(errno));
		// goto cleanup;
	}

	/* Attach to tc ingress */
	if (tc_attach(skel->progs.tc_ingress_prog,
				  tc_hook.ifindex, BPF_TC_INGRESS) < 0)
	{
		fprintf(stderr, "Failed to attach to TC ingress: %s!\n", strerror(errno));
		goto cleanup;
	}

	/* Attach to tc egress */
	if (tc_attach(skel->progs.tc_egress_prog,
				  tc_hook.ifindex, BPF_TC_EGRESS) < 0)
	{
		fprintf(stderr, "Failed to attach to TC egress: %s!\n", strerror(errno));
		goto cleanup;
	}

	/* Trace tcp_retransmit_skb */
	kprobe = skel->progs.tcp_retransmit_skb_trace;
	if (bpf_program__attach(kprobe) < 0)
	{
		fprintf(stderr, "Failed to attach tracepoint: %s\n", strerror(errno));
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR)
	{
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("Successfully started!\n");

	/* Bump eBPF counters */
	while (!stop)
	{
		bump_counters(skel->maps.tcp_stats);
		sleep(1);
	}

cleanup:
	tcp_tracing_bpf__destroy(skel);
	bpf_tc_hook_destroy(&tc_hook);

	return -1;
}
