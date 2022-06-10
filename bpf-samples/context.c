#include "bpf.h"
#include "kprobe.h"

int bpf_prog(struct kprobe_bpf_ctx *ctx) {
  // report tracepoint type
  if (ctx->ptype == 0)
    bpf_trace_printk("kprobe", 0, 0, 0);
  else if (ctx->ptype == 1)
    bpf_trace_printk("kretprobe@entry", 0, 0, 0);
  else
    bpf_trace_printk("kretprobe@exit", 0, 0, 0);

  // report tracepoint address
  bpf_trace_printk("\taddr = {}\n", ctx->paddr, 0, 0);

  // report registers
  for (int i = 0; i < 32; ++i) {
    bpf_trace_printk("r{}", i, 0, 0);
    if (i < 10)
      bpf_trace_printk(" ", 0, 0, 0);
    bpf_trace_printk(" = {}\n", ctx->tf.regs[i], 0, 0);
  }

  // recover return result from a0
  bpf_trace_printk("a0 = {}\n", ctx->tf.general.a0, 0, 0);
  // char *ret_addr = (char *)ctx->tf.general.a0;
  // char enum_flag = *ret_addr;
  // if (enum_flag == 0) {
  //   size_t retvalue = *(size_t *)(ret_addr + 8);
  //   bpf_trace_printk("ret = Ok({})\n", retvalue, 0, 0);
  // } else if (enum_flag == 1) {
  //   size_t syserror_flag = *(size_t *)(ret_addr + 8);
  //   bpf_trace_printk("ret = Err({})\n", syserror_flag, 0, 0);
  // } else {
  //   bpf_trace_printk("failed to fetch SysResult return value\n", 0, 0, 0);
  // }

  return 0;
}