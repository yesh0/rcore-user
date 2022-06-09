%.o: %.c
	clang -target bpf -O1 -c -o $@ $<

all: map.o time1.o time2.o
