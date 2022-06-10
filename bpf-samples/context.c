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
  bpf_trace_printk("\taddr = {}\n", ctx->paddr, 0, 0);

  const char *reg_names[] = {
      "zero", "ra  ", "sp  ", "gp  ", "tp  ", "t0  ", "t1  ", "t2  ",
      "s0  ", "s1  ", "a0  ", "a1  ", "a2  ", "a3  ", "a4  ", "a5  ",
      "a6  ", "a7  ", "s2  ", "s3  ", "s4  ", "s5  ", "s6  ", "s7  ",
      "s8  ", "s9  ", "s10 ", "s11 ", "t3  ", "t4  ", "t5  ", "t6  "};

  // report registers
  for (int i = 0; i < 32; ++i) {
    bpf_trace_printk("r{}", i, 0, 0);
    if (i < 10)
      bpf_trace_printk(" ", 0, 0, 0);
    bpf_trace_puts("(");
    bpf_trace_print_str(reg_names[i], 4);
    bpf_trace_puts(")");
    bpf_trace_printk(" = {}\n", ctx->tf.general[i], 0, 0);
  }

  return 0;
}