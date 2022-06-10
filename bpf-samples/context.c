#include "bpf.h"
#include "kprobe.h"

int bpf_prog(struct kprobe_bpf_ctx *ctx) {
  // report tracepoint type
  if (ctx->ptype == 0)
    bpf_trace_printk("kprobe\n", 0, 0, 0);
  else if (ctx->ptype == 1)
    bpf_trace_printk("kretprobe@entry\n", 0, 0, 0);
  else
    bpf_trace_printk("kretprobe@exit\n", 0, 0, 0);

  // report tracepoint address
  bpf_trace_printk("\taddr = {:x}\n", ctx->paddr, 0, 0);

  // report registers
  for (int i = 0; i < 8; ++i) {
    for (int j = 0; j < 4; ++j) {
      int reg = j + i * 4;
      bpf_trace_printk("r{} {:x}", reg, ctx->tf.general[reg], 0);
    }
    bpf_trace_printk("\n", 0, 0, 0);
  }

  return 0;
}