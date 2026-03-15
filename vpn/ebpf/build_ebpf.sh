#!/bin/bash
set -e

# 检测架构：TARGETARCH (Buildx) 或根据内核头路径
if [ -d "/usr/src/kernels" ] && [ -n "$(ls -A /usr/src/kernels 2>/dev/null)" ]; then
    KERNEL_HEADERS_DIR=$(ls -d /usr/src/kernels/* 2>/dev/null | head -1)
elif [ -d "/usr/src/kernel-headers" ]; then
    KERNEL_HEADERS_DIR=/usr/src/kernel-headers
else
    KERNEL_HEADERS_DIR=/usr/include
fi

if [ "${TARGETARCH}" = "arm64" ] || echo "${KERNEL_HEADERS_DIR}" | grep -q aarch64; then
    BPF_ARCH_DEF="-D__TARGET_ARCH_arm64"
    ARCH_PATH="arch/arm64"
    # -mcpu=v4 fixes "Branch target out of insn range" (LLVM bug with v1 on ARM64)
    BPF_MCPU="-mcpu=v4"
else
    BPF_ARCH_DEF="-D__TARGET_ARCH_x86"
    ARCH_PATH="arch/x86"
    BPF_MCPU=""
fi

CFLAGS="${BPF_MCPU} -O2 -g -target bpf -mllvm -bpf-stack-size=16384 -D__BPF__ ${BPF_ARCH_DEF} -U__KERNEL__ -D__BPF_TRACING__ -D__no_sanitize_or_inline=inline -D__no_kasan_or_inline=inline -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wno-gnu-variable-sized-type-not-at-end -Wno-address-of-packed-member -Wno-tautological-compare -Wno-unknown-warning-option -Wno-macro-redefined -Wno-incompatible-library-redeclaration -Wno-#warnings -include /app/vpn/ebpf/src/bpf_compat.h -I/usr/include -I${KERNEL_HEADERS_DIR}/include/uapi -I${KERNEL_HEADERS_DIR}/${ARCH_PATH}/include/uapi -I${KERNEL_HEADERS_DIR}/${ARCH_PATH}/include/generated/uapi -I${KERNEL_HEADERS_DIR}/include/generated/uapi -I${KERNEL_HEADERS_DIR}/include -I${KERNEL_HEADERS_DIR}/${ARCH_PATH}/include -I${KERNEL_HEADERS_DIR}/${ARCH_PATH}/include/generated"

echo "Building eBPF: arch=${ARCH_PATH}, headers=${KERNEL_HEADERS_DIR}"

cd /app/vpn/ebpf
CGO_ENABLED=1 GOPACKAGE=ebpf go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "${CFLAGS}" -target bpf -no-strip -no-global-types -go-package ebpf xdp ./src/xdp_program.c
CGO_ENABLED=1 GOPACKAGE=ebpf go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "${CFLAGS}" -target bpf -no-strip -no-global-types -go-package ebpf tc_nat ./src/tc_nat.c
