cd ucore/build; make -j; cd ../..
cp ucore/build/riscv64/bpf_test build/riscv64/
make sfsimg PREBUILT=1 ARCH=riscv64
