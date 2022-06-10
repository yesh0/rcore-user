#include "bpf.h"
#include "kprobe.h"

int bpf_prog(struct kprobe_bpf_ctx *ctx) {
  bpf_trace_printk("probe type = {}", ctx->ptype, 0, 0);
  bpf_trace_printk("probe addr = {}", ctx->paddr, 0, 0);

  for (int i = 0; i < 32; ++i) {
    bpf_trace_printk("register {} = {}", i, ctx->tf.general[i], 0);
  }

  return 0;
}