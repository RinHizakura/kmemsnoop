/* clang-format off */

/* These header file should be included first and in sequence,
 * because our following included file may depend on these. Turn
 * off clang-format to achieve this purpose. */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
/* clang-format on */

#include "msg.h"
#include "utils.h"

const volatile u32 bp_type;
const volatile u64 bp_len;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    /* About 240 hits in flight between two polls. */
    __uint(max_entries, 256 * 1024);
} msg_ringbuf SEC(".maps");

u64 MSG_ID = 0;

/* Never touched: it only puts the message layout into BTF so that the
 * skeleton generates the matching Rust type for src/msg.rs. */
msg_t msg_layout;

SEC("perf_event")
int perf_event_handler(struct bpf_perf_event_data *ctx)
{
    // Get the event timestamp as soon as possible
    u64 timestamp = bpf_ktime_get_ns();
    u64 id = __sync_add_and_fetch(&MSG_ID, 1);

    msg_t *msg = bpf_ringbuf_reserve(&msg_ringbuf, sizeof(*msg), 0);
    if (!msg)
        return 0;

    msg->id = id;
    msg->timestamp = timestamp;
    msg->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&msg->cmd, sizeof(msg->cmd));

    msg->kstack_sz = bpf_get_stack(ctx, msg->kstack, sizeof(msg->kstack), 0);

    /* An execute watchpoint has no accessed data. */
    msg->has_data = bp_type != HW_BREAKPOINT_X;
    msg->addr = ctx->addr;
    /* Zero first: bp_len may be < 8, and a failed read leaves the
     * destination untouched, so the unread bytes must not be garbage. */
    msg->val = 0;
    if (msg->has_data && ctx->addr) {
        long err = bpf_core_read(&msg->val, bp_len, (void *) ctx->addr);
        if (err)
            bpf_printk("Fail to read %d bytes at %llx: %ld", bp_len, ctx->addr,
                       err);
    }

    bpf_ringbuf_submit(msg, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
