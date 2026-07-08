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
    __uint(max_entries, 4096);
} msg_ringbuf SEC(".maps");

u64 MSG_ID = 0;

static msg_ent_t *get_message(msg_type_t type, u64 timestamp)
{
    pid_t pid = (bpf_get_current_pid_tgid() >> 32);
    size_t total_size = sizeof(msg_ent_t);

    switch (type) {
    case MSG_TYPE_STACK:
        total_size += sizeof(stack_msg_t);
        break;
    case MSG_TYPE_DATA:
        total_size += sizeof(data_msg_t);
        break;
    default:
        break;
    }

    u64 id = __sync_add_and_fetch(&MSG_ID, 1);

    msg_ent_t *ent = bpf_ringbuf_reserve(&msg_ringbuf, total_size, 0);
    if (!ent) {
        bpf_printk("Drop message entry %d", id);
        return NULL;
    }
    ent->id = id;
    ent->type = type;
    ent->pid = pid;
    ent->timestamp = timestamp;
    bpf_get_current_comm(&ent->cmd, sizeof(ent->cmd));

    return ent;
}


static void submit_message(msg_ent_t *ent)
{
    bpf_printk("Submit message id=%d\n", ent->id);
    bpf_ringbuf_submit(ent, 0);
}

static void submit_msg_stack(struct bpf_perf_event_data *ctx, u64 timestamp)
{
    msg_ent_t *ent;
    stack_msg_t *stack_msg;

    ent = get_message(MSG_TYPE_STACK, timestamp);
    if (!ent)
        return;

    stack_msg = GET_INNER_MSG(ent, stack_msg_t);

    stack_msg->kstack_sz =
        bpf_get_stack(ctx, stack_msg->kstack, sizeof(stack_msg->kstack), 0);

    submit_message(ent);
}

static void submit_msg_data(struct bpf_perf_event_data *ctx, u64 timestamp)
{
    msg_ent_t *ent;
    data_msg_t *data_msg;
    void *data_ptr = (void *) ctx->addr;

    /* Don't share this type of message if this is an
     * executable point */
    if (bp_type == HW_BREAKPOINT_X)
        return;

    ent = get_message(MSG_TYPE_DATA, timestamp);
    if (!ent)
        return;

    data_msg = GET_INNER_MSG(ent, data_msg_t);

    data_msg->addr = ctx->addr;
    /* Zero first: bp_len may be < 8, and a failed read leaves the
     * destination untouched, so the unread bytes must not be garbage. */
    data_msg->val = 0;
    if (data_ptr) {
        long err = bpf_core_read(&data_msg->val, bp_len, data_ptr);
        if (err)
            bpf_printk("Fail to read %d bytes at %llx: %ld", bp_len, ctx->addr,
                       err);
    }

    submit_message(ent);
}

SEC("perf_event")
int perf_event_handler(struct bpf_perf_event_data *ctx)
{
    // Get the event timestamp as soon as possible
    u64 timestamp = bpf_ktime_get_ns();

    submit_msg_stack(ctx, timestamp);
    submit_msg_data(ctx, timestamp);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
