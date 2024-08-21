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

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} msg_ringbuf SEC(".maps");

u64 MSG_ID = 0;

static msg_ent_t *get_message(msg_type_t type)
{
    size_t total_size = sizeof(msg_ent_t);

    switch (type) {
    case MSG_TYPE_STACK:
        total_size += sizeof(stack_msg_t);
    default:
        break;
    }

    MSG_ID++;

    msg_ent_t *ent = bpf_ringbuf_reserve(&msg_ringbuf, total_size, 0);
    if (!ent) {
        bpf_printk("Drop message entry %d", MSG_ID);
        return NULL;
    }
    ent->id = MSG_ID;
    ent->type = type;

    return ent;
}


static void submit_message(msg_ent_t *ent)
{
    bpf_printk("Submit message id=%d\n", ent->id);
    bpf_ringbuf_submit(ent, 0);
}

SEC("perf_event")
int perf_event_handler(UNUSED struct pt_regs *ctx)
{
    msg_ent_t *ent;
    stack_msg_t *stack_msg;

    ent = get_message(MSG_TYPE_STACK);
    if (!ent)
        return -1;

    stack_msg = GET_INNER_MSG(ent, stack_msg_t);

    stack_msg->kstack_sz =
        bpf_get_stack(ctx, stack_msg->kstack, sizeof(stack_msg->kstack), 0);

    submit_message(ent);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
