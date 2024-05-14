ARCH ?= $(shell uname -p)

ifeq ($(ARCH), aarch64)
	CROSS_COMPILE = aarch64-unknown-linux-gnu
	LINKER = CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER
	EXPORT_PATH = $(LINKER)=$(CROSS_COMPILE)-gcc
	CARGO_OPT = --target $(CROSS_COMPILE)
	OUT = target/$(CROSS_COMPILE)/debug
else
	EXPORT_PATH =
	CARGO_OPT =
	OUT = target/debug
endif

BIN = $(OUT)/memwatch
VMLINUX_H = vmlinux.h
GIT_HOOKS := .git/hooks/applied
SRCS = $(shell find ./bpf -name '*.c')
SRCS += $(shell find ./src -name '*.rs')

CFLAGS = -Wall -Wextra -Werror

all: $(BIN) $(GIT_HOOKS)

$(GIT_HOOKS):
	@scripts/install-git-hooks
	@echo

$(BIN): $(SRCS) $(VMLINUX_H)
	$(EXPORT_PATH) cargo build $(CARGO_OPT)

$(VMLINUX_H):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

check:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

clean:
	cargo clean
