#include <bpf.h>
#include <ulib.h>
#include <stdio.h>

#define MAX_ENTRIES 32

int main()
{
    int key;
    uint64_t value;

    int fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(key), sizeof(value), MAX_ENTRIES);
    assert(fd > 0);

    key = 3;
    assert(bpf_lookup_elem(fd, &key, &value) == 0);
    assert(value == 0);

    key = 3;
    value = 0x1122334455667788LL;
    assert(bpf_update_elem(fd, &key, &value, 0) == 0);

    key = MAX_ENTRIES + 1;
    assert(bpf_update_elem(fd, &key, &value, 0) < 0); // this should fail

    key = 3;
    assert(bpf_delete_elem(fd, &key) < 0); // this should fail

    assert(bpf_lookup_elem(fd, &key, &value) == 0);
    assert(value == 0x1122334455667788LL);

    cprintf("bpf map tests OK\n");
    return 0;
}
