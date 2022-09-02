# TCP Trace - Hackathon Project

TCP Trace is a PoC implementation for the [Hackathon Idea](https://hackbox.microsoft.com/project/772). The idea is to detect network errors by tracing internal TCP state on Linux:

>This project aims to isolate network-related errors by tracing the server-side TCP Retransmits at the node level. The project will keep retransmit counts per service >identifier like cgroup and port. It will allow early detection of network-related issues, which will help during an incident, and, in some cases, help prevent >customer-impacting problems.

TCP Trace uses three [eBPF](https://ebpf.io/what-is-ebpf/) programs to hook into various **attach points** in the Linux kernel:

- tc ingress: Number of incoming TCP packets.
- tc egress: Number of outgoing TCP packets.
- tcp_retransmit_skb: Number of TCP retransmits.

## Compilation



