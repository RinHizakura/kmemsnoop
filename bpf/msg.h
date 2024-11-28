#ifndef MSG_H
#define MSG_H

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 127
#endif

#define GET_INNER_MSG(ent, typ) ((typ *) (ent->inner))

typedef enum {
    MSG_TYPE_STACK = 0,
    MSG_TYPE_DATA,
} msg_type_t;

#define TASK_COMM_LEN 16
typedef struct {
    u64 id;
    u64 type;
    u64 pid;
    char cmd[TASK_COMM_LEN];

    u8 inner[0];
} msg_ent_t;

typedef u64 stack_trace_t[PERF_MAX_STACK_DEPTH];

typedef struct {
    u64 kstack_sz;
    stack_trace_t kstack;
} stack_msg_t;

typedef struct {
    u64 addr;
    u64 val;
} data_msg_t;

#endif
