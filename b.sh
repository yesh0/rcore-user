#!/bin/bash

mkdir -p ucore/build
cd ucore/build; cmake .. -DARCH=riscv64; make -j; cd ../..
cp ucore/build/riscv64/bpf_test build/riscv64/
cp ucore/build/riscv64/bmonitor build/riscv64/
cd bpf-samples; make; cd ..
cp bpf-samples/*.o build/riscv64/
make sfsimg PREBUILT=1 ARCH=riscv64
