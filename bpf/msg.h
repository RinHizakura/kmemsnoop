#ifndef MSG_H
#define MSG_H

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 127
#endif

#define TASK_COMM_LEN 16

/* One record per watchpoint hit. The layout is the wire format that
 * src/msg.rs decodes, through the skeleton's BTF-generated type. The tag
 * must not collide with a kernel type from vmlinux.h (`struct msg` does),
 * or member accesses turn into CO-RE relocations against kernel BTF. */
typedef struct kmemsnoop_msg {
    /* Counted before the ring buffer reservation, so a gap in ids is
     * the number of hits that were dropped. */
    u64 id;
    u64 timestamp;
    u64 pid;
    char cmd[TASK_COMM_LEN];

    /* addr and val are only filled for data watchpoints. */
    u64 has_data;
    u64 addr;
    u64 val;

    /* Byte count from bpf_get_stack(), or a negative errno. */
    s64 kstack_sz;
    u64 kstack[PERF_MAX_STACK_DEPTH];
} msg_t;

#endif
