// Adopted from - https://github.com/iovisor/bcc/blob/master/tools/tcptop.py

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct ipv4_key_t {
    u32 pid;
    char name[TASK_COMM_LEN];
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
};
BPF_HASH(ipv4_send_bytes, struct ipv4_key_t);

struct ipv6_key_t {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u32 pid;
    char name[TASK_COMM_LEN];
    u16 lport;
    u16 dport;
    u64 __pad__;
};
BPF_HASH(ipv6_send_bytes, struct ipv6_key_t);
BPF_HASH(ipv6_recv_bytes, struct ipv6_key_t);
BPF_HASH(sock_store, u32, struct sock *);


struct ipv4_data_t {
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
    u64 rx_b;
    u64 tx_b;
    u64 span_us;
    u32 state;
};
BPF_PERF_OUTPUT(ipv4_events);
struct ipv6_data_t {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 lport;
    u16 dport;
    u64 rx_b;
    u64 tx_b;
    u64 span_us;
};
BPF_PERF_OUTPUT(ipv6_events);

BPF_HASH(birth, struct sock *, u64);


static int tcp_send_entry(struct sock *sk)
{
    if (container_should_be_filtered()) {
        return 0;
    }
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    u32 tid = bpf_get_current_pid_tgid();
    u16 family = sk->__sk_common.skc_family;
    sock_store.update(&tid, &sk);

    // Recoard the birth of the sequence
    u64 ts = bpf_ktime_get_ns();
    birth.update(&sk, &ts);

    return 0;
}

// Track in new send events

// It could be either tcp_sendmsg or tcp_sendpage
// http://vger.kernel.org/~davem/tcp_output.html
int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size)
{
    return tcp_send_entry(sk);
}

int kprobe__tcp_sendpage(struct pt_regs *ctx, struct sock *sk, struct page *page, int offset, size_t size)
{
    return tcp_send_entry(sk);
}


// Collect data about the send event at the end of function execution

static int tcp_sendstat(int size)
{
    if (container_should_be_filtered()) {
        return 0;
    }

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    u32 tid = bpf_get_current_pid_tgid();
    struct sock **sockpp;
    sockpp = sock_store.lookup(&tid);
    if (sockpp == 0) {
        return 0; //miss the entry
    }
    struct sock *sk = *sockpp;
    u16 dport = 0, family;
    bpf_probe_read_kernel(&family, sizeof(family),
        &sk->__sk_common.skc_family);
    
    if (family == AF_INET) {
        struct ipv4_key_t ipv4_key = {.pid = pid};
        bpf_get_current_comm(&ipv4_key.name, sizeof(ipv4_key.name));
        bpf_probe_read_kernel(&ipv4_key.saddr, sizeof(ipv4_key.saddr),
            &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&ipv4_key.daddr, sizeof(ipv4_key.daddr),
            &sk->__sk_common.skc_daddr);
        bpf_probe_read_kernel(&ipv4_key.lport, sizeof(ipv4_key.lport),
            &sk->__sk_common.skc_num);
        bpf_probe_read_kernel(&dport, sizeof(dport),
            &sk->__sk_common.skc_dport);
        ipv4_key.dport = ntohs(dport);
        ipv4_send_bytes.increment(ipv4_key, size);

    } else if (family == AF_INET6) {
        struct ipv6_key_t ipv6_key = {.pid = pid};
        bpf_get_current_comm(&ipv6_key.name, sizeof(ipv6_key.name));
        bpf_probe_read_kernel(&ipv6_key.saddr, sizeof(ipv6_key.saddr),
            &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&ipv6_key.daddr, sizeof(ipv6_key.daddr),
            &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&ipv6_key.lport, sizeof(ipv6_key.lport),
            &sk->__sk_common.skc_num);
        bpf_probe_read_kernel(&dport, sizeof(dport),
            &sk->__sk_common.skc_dport);
        ipv6_key.dport = ntohs(dport);
        ipv6_send_bytes.increment(ipv6_key, size);
    }
    sock_store.delete(&tid);

    // else drop

    return 0;
}

int kretprobe__tcp_sendmsg(struct pt_regs *ctx)
{
    int size = PT_REGS_RC(ctx);
    if (size > 0)
        return tcp_sendstat(size);
    else
        return 0;
}

int kretprobe__tcp_sendpage(struct pt_regs *ctx)
{
    int size = PT_REGS_RC(ctx);
    if (size > 0)
        return tcp_sendstat(size);
    else
        return 0;
}



/*
 * tcp_recvmsg() would be obvious to trace, but is less suitable because:
 * - we'd need to trace both entry and return, to have both sock and size
 * - misses tcp_read_sock() traffic
 * we'd much prefer tracepoints once they are available.
 */
int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied)
{
    if (container_should_be_filtered()) {
        return 0;
    }

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    

    u16 dport = 0, family = sk->__sk_common.skc_family;
    u64 *val, zero = 0;

    if (copied <= 0)
        return 0;

    // Calculate lifespan
    u64 *tsp, delta_us;
    tsp = birth.lookup(&sk);
    if (tsp == 0) {
        // whoami.delete(&sk);     // may not exist
        return 0;               // missed create
    }
    delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
    birth.delete(&sk);

    
    if (family == AF_INET) {
        struct ipv4_key_t ipv4_key = {.pid = pid};
        bpf_get_current_comm(&ipv4_key.name, sizeof(ipv4_key.name));
        ipv4_key.saddr = sk->__sk_common.skc_rcv_saddr;
        ipv4_key.daddr = sk->__sk_common.skc_daddr;
        ipv4_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        ipv4_key.dport = ntohs(dport);


        u64 *tx_b = ipv4_send_bytes.lookup(&ipv4_key);
        if (tx_b == 0) {
            // whoami.delete(&sk);     // may not exist
            return 0;               // missed create
        }
        ipv4_send_bytes.delete(&ipv4_key);


        struct ipv4_data_t data4 = {};
        data4.span_us = delta_us;
        data4.rx_b = copied;
        data4.tx_b = *tx_b;
        data4.saddr = sk->__sk_common.skc_rcv_saddr;
        data4.lport = sk->__sk_common.skc_num;
        data4.daddr = sk->__sk_common.skc_daddr;
        data4.dport = ntohs(dport);

        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));

    } else if (family == AF_INET6) {
        struct ipv6_key_t ipv6_key = {.pid = pid};
        bpf_get_current_comm(&ipv6_key.name, sizeof(ipv6_key.name));
        bpf_probe_read_kernel(&ipv6_key.saddr, sizeof(ipv6_key.saddr),
            &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&ipv6_key.daddr, sizeof(ipv6_key.daddr),
            &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        ipv6_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        ipv6_key.dport = ntohs(dport);
        // ipv6_recv_bytes.increment(ipv6_key, copied);

        u64 *tx_b = ipv6_send_bytes.lookup(&ipv6_key);
        if (tx_b == 0) {
            // whoami.delete(&sk);     // may not exist
            return 0;               // missed create
        }
        ipv6_send_bytes.delete(&ipv6_key);

        struct ipv6_data_t data6 = {};
        data6.span_us = delta_us;
        data6.rx_b = copied;
        data6.tx_b = *tx_b;
        data6.saddr = ipv6_key.saddr;
        data6.lport = ipv6_key.lport;
        data6.daddr = ipv6_key.daddr;
        data6.dport = ntohs(dport);

        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }
    // else drop

    return 0;
}