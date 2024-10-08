ARCH ?= $(shell uname -p)

ifeq ($(ARCH), aarch64)
	LINKER = CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER
	CROSS_COMPILE = aarch64-unknown-linux-gnu
	EXPORT_PATH = $(LINKER)=$(CROSS_COMPILE)-gcc
	CARGO_OPT = --target $(CROSS_COMPILE)
else
	CROSS_COMPILE =
	EXPORT_PATH =
	CARGO_OPT =
ifneq ("$(wildcard /sys/kernel/btf/vmlinux)", "")
	VMLINUX_BTF = /sys/kernel/btf/vmlinux
endif
endif

BUILD_FEATURE=

ifeq ("$(wildcard /proc/kcore)", "")
	BUILD_FEATURE += --no-default-features kexpr
endif

ifeq ($(VMLINUX_BTF), )
	VMLINUX_BTF = vmlinux.btf
endif

OUT = target/$(CROSS_COMPILE)/debug


VMLINUX_H = vmlinux.h
BIN = $(OUT)/kmemsnoop
GIT_HOOKS := .git/hooks/applied
SRCS = $(shell find ./bpf -name '*.c')
SRCS += $(shell find ./src -name '*.rs')

CFLAGS = -Wall -Wextra -Werror

all: $(BIN) $(GIT_HOOKS)

$(GIT_HOOKS):
	@scripts/install-git-hooks
	@echo

$(BIN): $(SRCS) $(VMLINUX_H)
	git submodule update --init --recursive
	$(EXPORT_PATH) cargo build $(BUILD_FEATURE) $(CARGO_OPT)

$(VMLINUX_BTF):
ifeq ($(VMLINUX), )
	$(error Please specific vmlinux with VMLINUX=)
endif
	pahole --btf_encode_detached $@ $(VMLINUX)

$(VMLINUX_H): $(VMLINUX_BTF)
	bpftool btf dump file $< format c > $@

check:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

# FIXME: This will create file with super user permission. We
# better avoid this if possible.
test:
	sudo cargo test --features kexpr --target-dir test_build

clean:
	cargo clean

