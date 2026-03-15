//go:build ignore
// +build ignore

package main

// generate.go: bpf2go build. C为主、Go只负责装载和map操作.
// Run: go generate ./vpn/ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -mllvm -bpf-stack-size=16384" -target bpf -no-strip -no-global-types -go-package ebpf xdp ./src/xdp_program.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -mllvm -bpf-stack-size=16384" -target bpf -no-strip -no-global-types -go-package ebpf tc_nat ./src/tc_nat.c
