OUT = target/debug

BIN = $(OUT)/memwatch
VMLINUX_H = vmlinux.h
GIT_HOOKS := .git/hooks/applied
SRCS = $(shell find ./bpf -name '*.c')
SRCS += $(shell find ./src -name '*.rs')

CFLAGS = -Wall -Wextra -Werror

vpath %.c $(sort $(dir $(TEST_SRCS)))

all: $(BIN) $(GIT_HOOKS) $(TEST_OBJ)

$(GIT_HOOKS):
	@scripts/install-git-hooks
	@echo

$(BIN): $(SRCS) $(VMLINUX_H)
	cargo build

$(TEST_OUT)/%.out: %.c
	gcc $(CFLAGS) $< -o $@

$(VMLINUX_H):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

check:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

clean:
	cargo clean
