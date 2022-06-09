#ifndef __LIBS_KPROBE_H__
#define __LIBS_KPROBE_H__

typedef unsigned long long size_t;

#define KPROBE_TYPE_KPROBE 0
#define KRPOBE_TYPE_KRETPROBE_ENTRY 1
#define KPROBE_TYPE_KRETPROBE_EXIT 2

struct kprobe_bpf_ctx {
  size_t ptype;
  size_t paddr;
  struct {
    size_t general[32];
    size_t sstatus;
    size_t sepc;
  } tf;
};

#endif