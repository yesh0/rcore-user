#include "bpf.h"
#include "kprobe.h"

static const char *reg_names[] = {
    "zero", "ra", "sp", "gp", "tp",  "t0",  "t1", "t2", "s0", "s1", "a0",
    "a1",   "a2", "a3", "a4", "a5",  "a6",  "a7", "s2", "s3", "s4", "s5",
    "s6",   "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"};

int bpf_prog(struct kprobe_bpf_ctx *ctx) {
  bpf_trace_printk("probe type = {}", ctx->ptype, 0, 0);
  bpf_trace_printk("probe addr = {}", ctx->paddr, 0, 0);

  for (int i = 0; i < 32; ++i) {
    const char *regname = reg_names[i];
    bpf_trace_printk("register {} = {}", (long)regname, ctx->tf.general[i], 0);
  }

  return 0;
}