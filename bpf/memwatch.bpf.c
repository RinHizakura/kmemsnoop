/* clang-format off */

/* These header file should be included first and in sequence,
 * because our following included file may depend on these. Turn
 * off clang-format to achieve this purpose. */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
/* clang-format on */

#include "utils.h"

SEC("perf_event")
int perf_event_handler(UNUSED struct pt_regs *ctx)
{
    int test = 0;
    bpf_printk("PERF_EVENT %d", test);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
