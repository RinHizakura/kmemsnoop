ARCH ?= $(shell uname -p)

ifeq ($(ARCH), aarch64)
	VMLINUX_DIR = vmlinux/arm64
	LINKER = CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER
	CROSS_COMPILE = aarch64-unknown-linux-gnu
	EXPORT_PATH = $(LINKER)=$(CROSS_COMPILE)-gcc
	CARGO_OPT = --target $(CROSS_COMPILE)
else
	VMLINUX_DIR = .
	CROSS_COMPILE =
	EXPORT_PATH =
	CARGO_OPT =
endif

OUT = target/$(CROSS_COMPILE)/debug

# It is recommanded to build vmlinux.h from scratch by bpftool, but
# here we use the prebuilt header in cross compilation for convenient.
VMLINUX_H = $(VMLINUX_DIR)/vmlinux.h
BIN = $(OUT)/memwatch
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
