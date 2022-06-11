#include <ulib.h>
#include <stdio.h>
#include <string.h>
#include <dir.h>
#include <file.h>
#include <error.h>
#include <unistd.h>
#include <syscall.h>
#include <bpf.h>
#include <stat.h>

#define printf(...)                     cprintf(__VA_ARGS__)

#define BUFSIZE                         512
#define WHITESPACE                      " \t\r\n"
#define SYMBOLS                         ""

#define BEL 0x07
#define BS 0x08
#define ESC 0x1b
#define DEL 0x7f

static inline void putc(char c) {
    sys_write(1, &c, 1);
}

static int atoi(const char *s) {
    int v = 0;
    int neg = 0;
    if (*s == '-') {
        neg = 1;
        ++s;
    }
    while (*s) {
        v = v * 10 + *s++ - '0';
    }
    return neg ? -v : v;
}

static inline int isdigit(char c) {
    return '0' <= c && c <= '9';
}

static inline int is_uint(const char *s) {
    if (!s)
        return 0;
    while (*s) {
        if (!isdigit(*s))
            return 0;
        ++s;
    }
    return 1;
}

int gettoken(char **p1, char **p2) {
    char *s;
    if ((s = *p1) == NULL) {
        return 0;
    }
    while (strchr(WHITESPACE, *s) != NULL) {
        *s ++ = '\0';
    }
    if (*s == '\0') {
        return 0;
    }

    *p2 = s;
    int token = 'w';
    if (strchr(SYMBOLS, *s) != NULL) {
        token = *s, *s ++ = '\0';
    } else {
        bool flag = 0;
        while (*s != '\0' && (flag || strchr(WHITESPACE SYMBOLS, *s) == NULL)) {
            if (*s == '"') {
                *s = ' ', flag = !flag;
            }
            s ++;
        }
    }
    *p1 = (*s != '\0' ? s : NULL);
    return token;
}

char *readline(const char *prompt) {
    static char buffer[BUFSIZE];
    if (prompt != NULL) {
        printf("%s", prompt);
    }
    int i = 0;
    while (1) {
        char c = getchar();
        if (c == 3) {
            return NULL;
        } else if (c == BS || c == DEL) {
            if (i > 0) {
                putc(BS);
                putc(' ');
                putc(ESC);
                putc('[');
                putc('D');
                --i;
            } else {
                putc(BEL);
            }
        } else if (c == '\n' || c == '\r') {
            putc('\n');
            buffer[i] = '\0';
            break;
        } else if (c >= ' ' && i < BUFSIZE - 1) {
            putc(c);
            buffer[i ++] = c;
        }
    }
    return buffer;
}

static char *elf_image = NULL;
static size_t elf_size;
static int elf_fd = -1;

void close_elf() {
    if (elf_fd > 0) {
        close(elf_fd);
        elf_fd = -1;
    }
    
    if (elf_image != NULL) {
        sys_munmap(elf_image, elf_size);
        elf_image = NULL;
    }
}

int open_elf(const char *path) {
    // close current file first
    close_elf();

    elf_fd = open(path, O_RDONLY);
    if (elf_fd < 0) {
        printf("failed to open %s\n", path);
        return -1;
    }

    struct stat stat;
    fstat(elf_fd, &stat);
    elf_size = stat.st_size;

    long ret = (long) sys_mmap(NULL, elf_size, 3, 32, -1, 0);
    if (ret <= 0) {
        printf("mmap failed! ret = %ld\n", ret);
        close(elf_fd);
        return -1;
    }
    elf_image = (char *) ret;
    read(elf_fd, elf_image, elf_size);
    return 0;
}

void quit() {
    close_elf();
    // TODO: release all eBPF programs and maps
}

struct map_info {
    enum bpf_map_type map_type;
    int key_size;
    int value_size;
    int max_entries;
    int fd;
};

struct map_injection_info {
    int map_nr;
    const char *symbol;
};

#define MAX_NR_MAPS 32
static int nr_maps = 0, nr_map_injections = 0;
static struct map_info map_info_array[MAX_NR_MAPS];
static struct map_injection_info map_injections[MAX_NR_MAPS];
static struct bpf_map_fd_entry real_map_injections[MAX_NR_MAPS];
static char map_symbols[BUFSIZE];

int create_map(enum bpf_map_type type, int key_size, int value_size, int max_entries) {
    if (nr_maps >= MAX_NR_MAPS) {
        printf("<cm>: number of maps exceeds limit!\n");
        return -1;
    }

    int fd = bpf_create_map(type, key_size, value_size, max_entries);
    if (fd < 0) {
        printf("<cm>: bpf_create_map failed! ret = %d\n", fd);
        return -1;
    }

    struct map_info *p = &map_info_array[nr_maps++];
    p->map_type = type;
    p->key_size = key_size;
    p->value_size = value_size;
    p->max_entries = max_entries;
    p->fd = fd;
    printf("map [%d] created. fd = %#x\n", nr_maps - 1, fd);
    return 0;
}

int inject_maps(int argc, const char **argv) {
    if (argc %2 != 1) {
        printf("<inject> should have even numbered arguments\n");
        return -1;
    }

    int count = (argc - 1) / 2;
    int tot_len = 0;
    for (int i = 0; i < count; ++i) {
        const char *map_nr_str = argv[2 + i * 2];
        if (!is_uint(map_nr_str)) {
            printf("<inject>: \"%s\" is not an unsigned number\n", map_nr_str);
            return -1;
        }

        int map_nr = atoi(map_nr_str);
        if (map_nr >= nr_maps) {
            printf("<inject>: map index exceeds limit\n");
            return -1;
        }

        char *symbol = &map_symbols[tot_len];
        strcpy(symbol, argv[1 + i * 2]);
        tot_len += strlen(symbol) + 1;
 
        struct map_injection_info inj = {
            .map_nr = map_nr, .symbol = symbol
        };
        map_injections[i] = inj;
    }
    nr_map_injections = count;
    return 0;
}

#define MAX_NR_PROGS 8
static int nr_progs = 0;
static int prog_fds[MAX_NR_PROGS];

int load_program() {
    if (elf_image == NULL) {
        printf("<load>: no open ELF image\n");
        return -1;
    }
    if (nr_progs >= MAX_NR_PROGS) {
        printf("<load>: number of loaded programs exceeds limit\n");
        return -1;
    }

    for (int i = 0; i < nr_map_injections; ++i) {
        int map_nr = map_injections[i].map_nr;
        real_map_injections[i].name = map_injections[i].symbol;
        real_map_injections[i].fd = map_info_array[map_nr].fd; 
    }

    int fd = bpf_prog_load_ex(elf_image, elf_size, real_map_injections, nr_map_injections);
    if (fd < 0) {
        printf("<load>: bpf_prog_load_ex failed! ret = %d\n", fd);
        return -1;
    }
    prog_fds[nr_progs++] = fd;
    return 0;
}

int attach_program(int argc, const char **argv) {
    if (argc -1 != 2) {
        printf("<attach> should have 2 arguments\n");
        return -1;
    }
    if (!is_uint(argv[1])) {
        printf("<attach>: \"%s\" is not an unsigned number\n", argv[1]);
        return -1;
    }

    int prog_nr = atoi(argv[1]);
    if (prog_nr >= nr_progs) {
        printf("<attach>: PROG_NR exceeds limit\n");
        return -1;
    }
    int fd = prog_fds[prog_nr];
    int ret = bpf_prog_attach(argv[2], fd);
    if (ret < 0) {
        printf("<attach>: bpf_prog_attach failed! ret = %d\n", ret);
        return -1;
    }
    return 0;
}

void help() {
    printf("bmonitor: a simple monitor\n");
    printf("supported commands:\n");
    printf("\thelp: show this help\n");
    printf("\tquit: quit bmonitor\n");
    printf("\tsh: spawn a shell (busybox ash)\n");
    printf("\topen FILE: open an eBPF ELF image\n");
    printf("\tcm TYPE KEY_SZ VAL_SZ NR_ENTS: create an eBPF map\n");
    printf("\tls TYPE: list objects\n");
    printf("\tinject <SYMBOL MAP_NR>+: inject map information\n");
    printf("\tload: load current eBPF ELF object with injection info\n");
    printf("\tattach PROG TARGET: attach PROG to TARGET trace point\n");
    printf("\thist MAP_NR: treat map [MAP_NR] as a histogram and print it\n");
}

int list(int argc, const char **argv) {
    if (argc -1 < 1) {
        printf("<ls> should have more than 1 arguments\n");
        printf("<ls> TYPE: list objects of type TYPE\n");
        printf("supported TYPEs: map, inj (map injections), prog (loaded programs)\n");
        return -1;
    }

    const char *type = argv[1];
    if (strcmp(type, "map") == 0) {
        if (nr_maps > 0)
            printf("registered maps:\n");
        else
            printf("no registered maps.\n");
        for (int i = 0; i < nr_maps; ++i) {
            struct map_info *p = &map_info_array[i];
            printf("\tmap [%d] fd = %#x type = %d key_sz = %d val_sz = %d max_entries = %d\n",
                i, p->fd, p->map_type, p->key_size, p->value_size, p->max_entries);
        }
    } else if (strcmp(type, "inj") == 0) {
        if (nr_map_injections > 0)
            printf("map injection info:\n");
        else
            printf("no map injection info.\n");
        for (int i = 0; i < nr_map_injections; ++i) {
            struct map_injection_info *inj = &map_injections[i];
            struct map_info *map = &map_info_array[inj->map_nr];
            printf("\t\"%s\" <=> map [%d] fd = %#x\n", inj->symbol, inj->map_nr, map->fd);
        }
    } else if (strcmp(type, "prog") == 0) {
        if (nr_progs > 0)
            printf("loaded eBPF program info:\n");
        else
            printf("no loaded eBPF program.\n");
        for (int i = 0; i < nr_progs; ++i) {
            printf("\tprog [%d] fd = %#x\n", i, prog_fds[i]);
        }
    } else {
        printf("<ls>: TYPE \"%s\" is not supported\n", type);
        return -1;
    }
    return 0;
}

int hist(int argc, const char **argv) {
    if (argc -1 < 1) {
        printf("<hist> should have at least 1 argument\n");
        return -1;
    }
    if (!is_uint(argv[1])) {
        printf("<hist>: \"%s\" is not an unsigned number\n", argv[1]);
        return -1;
    }

    int map_nr = atoi(argv[1]);
    if (map_nr >= nr_maps) {
        printf("<hist>: MAP_NR exceeds limit\n");
        return -1;
    }
    int fd = map_info_array[map_nr].fd;
    int max_entries = map_info_array[map_nr].max_entries;

    int count, key = 0;
    uint64_t value;
    if (bpf_lookup_elem(fd, &key, &value) < 0) {
        printf("<hist>: failed to read count\n");
        return -1;
    }
    
    count = value;
    if (count < 0 || count >= max_entries) {
        printf("<hist>: histogram map already overflow.\n");
        count = max_entries - 1;
    }

    size_t size = 8 * count;
    uint64_t *buf = sys_mmap(NULL, size, 3, 32, -1, 0);
    
    uint64_t minv, maxv, width;
    minv = 0xffffffffffffffff;
    maxv = 0;
    for (int i = 1; i <= count; ++i) {
        if (bpf_lookup_elem(fd, &i, &value) < 0) {
            printf("<hist>: failed to read %d-th value\n", i);
            continue;
        }
        buf[i - 1] = value;
        if (minv > value)
            minv = value;
        if (maxv < value)
            maxv = value;
    }
    if (argc -1 >= 3) {
        uint64_t minv_override = strtol(argv[2], NULL, 10);
        uint64_t maxv_override = strtol(argv[3], NULL, 10);
        if (minv < maxv) {
            minv = minv_override, maxv = maxv_override;
        } else {
            printf("<hist>: bad range. value not changed.\n");
        }
    }

    #define NR_BINS 10
    static int bins[NR_BINS];
    width = (maxv - minv) / NR_BINS;
    memset(bins, 0, sizeof(bins));
    for (int i = 0; i < count; ++i) {
        int bin = (buf[i] - minv) / width;
        if (0 <= bin && bin < NR_BINS)
            ++bins[bin];
    }

    const int VALUE_BINS = 50;
    int max_count = 0;
    for (int i = 0; i < NR_BINS; ++i)
        if (max_count < bins[i])
            max_count = bins[i];
    for (int i = 0; i < NR_BINS; ++i) {
        uint64_t lo = minv + i * width;
        uint64_t hi = lo + width;
        printf("[%ld, %ld) ", lo, hi);
        /*
        if (i == NR_BINS - 1)
            printf("] ");
        else
            printf(") ");
        */

        int char_count;
        if (max_count >= VALUE_BINS) {
            char_count = bins[i] * VALUE_BINS / max_count;
        } else {
            char_count = bins[i];
        }
        while (char_count-- > 0)
            printf("*");
        printf(" %d\n", bins[i]);
    }

    sys_munmap(buf, size);
    return 0;
}

int
runcmd(char *cmd) {
    const char *argv[EXEC_MAX_ARG_NUM + 1];
    char *t;
    int argc, token, ret, stop = 0;

    argc = 0;
    while (!stop) {
        switch (token = gettoken(&cmd, &t)) {
        case 'w':
            if (argc == EXEC_MAX_ARG_NUM) {
                printf("error: too many arguments\n");
                return -1;
            }
            argv[argc++] = t;
            break;
        case 0:
            stop = 1;
            break;
        default:
            printf("error: bad return value %d from gettoken\n", token);
            return -1;
        }
    }

    if (argc == 0)
        return 0;

    if (strcmp(argv[0], "quit") == 0) {
        return 1;
    } else if (strcmp(argv[0], "sh") == 0) {
        int pid = fork();
        if (pid == 0) {
            argv[0] = "busybox";
            argv[1] = "ash";
            argv[2] = NULL;
            sys_execve(argv[0], argv, NULL);
        } else {
            waitpid(pid, &ret);
        }
    } else if (strcmp(argv[0], "help") == 0) {
        help();
    } else if (strcmp(argv[0], "open") == 0) {
        if (argc - 1 != 1)
            printf("<open> should have 1 argument\n");
        else {
            open_elf(argv[1]);
        }
    } else if (strcmp(argv[0], "cm") == 0) {
        if (argc - 1 != 4)
            printf("<cm> should have 4 arguments\n");
        else {
            if (strcmp(argv[1], "array") != 0) {
                printf("<cm> currently only support BPF_MAP_TYPE_ARRAY\n");
            } else {
                int key_sz = atoi(argv[2]);
                int val_sz = atoi(argv[3]);
                int max_entries = atoi(argv[4]);
                create_map(BPF_MAP_TYPE_ARRAY, key_sz, val_sz, max_entries);
            }
        }
    } else if (strcmp(argv[0], "hist") == 0) {
        hist(argc, argv);
    } else if (strcmp(argv[0], "inject") == 0) {
        inject_maps(argc, argv);
    } else if (strcmp(argv[0], "load") == 0) {
        load_program();
    } else if (strcmp(argv[0], "attach") == 0) {
        attach_program(argc, argv);
    } else if (strcmp(argv[0], "ls") == 0) {
        list(argc, argv);
    } else {
        printf("bmonitor: unrecognized command \"%s\". type \"help\" to see usage.\n", argv[0]);
    }
    return 0;
}

int
main(int argc, char **argv) {
    printf("welcome to bmonitor\n");

    char *buffer;
    while ((buffer = readline(">> ")) != NULL) {
        if (runcmd(buffer) > 0)
            break;
    }
    quit();
    return 0;
}
