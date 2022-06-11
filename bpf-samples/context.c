#include "bpf.h"
#include "kprobe.h"

int bpf_prog(struct kprobe_bpf_ctx *ctx) {
    // report tracepoint type
    if (ctx->ptype == 0)
        bpf_trace_puts("kprobe");
    else if (ctx->ptype == 1)
        bpf_trace_puts("kretprobe@entry");
    else
        bpf_trace_puts("kretprobe@exit");

    // report tracepoint address
    bpf_trace_printk("\taddr = {}\n", ctx->paddr, 0, 0);

    // report registers
    for (int i = 0; i < 32; ++i) {
        bpf_trace_printk("r{}", i, 0, 0);
        if (i < 10)
            bpf_trace_puts(" ");
        bpf_trace_printk(" = {}\n", ctx->tf.regs[i], 0, 0);
    }

    int read_ok = 0;
    size_t val;
    for (int i = 10; i < 18; ++i) {
        char flag;
        size_t addr = ctx->tf.regs[i];
        if (bpf_probe_read(&flag, 1, addr) != 0)
            continue;
        if (flag != 0 && flag != 1)
            continue;
        if (bpf_probe_read(&val, sizeof(size_t), addr + 8) != 0)
            continue;
        
        read_ok = 1;
        bpf_trace_printk("flag = {}, value = {}\n", flag, val, 0);
    }
    if (!read_ok)
        bpf_trace_puts("SysResult not found\n");

    return 0;
}
