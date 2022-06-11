# eBPF samples

这里是为rCore准备的eBPF样例程序，需要使用clang编译。

目前这里的程序有：
+ `map.c`：更新一个map并输出信息。
+ `time1.c`：计时程序的前半部分。
+ `time2.c`：计时程序的后半部分。
+ `context.c`：打印kprobe上下文。

## `bmonitor`的示例命令

+ 示例1

```
cm array 4 8 4
cm array 4 8 512
open time1.o
inject time_counters 0
load
open time2.o
inject time_counters 0 records 1
load
attach 0 kretprobe@entry:<rcore::syscall::Syscall>::sys_fork
attach 1 kretprobe@exit:<rcore::syscall::Syscall>::sys_fork
sh
```

+ 示例2

```
cm array 4 8 1
open map.o
inject map_fd 0
load
attach 0 kretprobe@entry:<rcore::syscall::Syscall>::sys_fork
```

+ 示例3

```
open context.o
load
attach 0 kretprobe@exit:<rcore::syscall::Syscall>::sys_bpf
```
