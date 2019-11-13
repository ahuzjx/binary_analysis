#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include "elf_parser.h"
#include "udis86.h"

void show_asm_instruction(long orig) {
	ud_t ud_object;
	ud_init(&ud_object);
	ud_set_input_buffer(&ud_object, (const uint8_t *)&orig, sizeof(orig));
	ud_set_mode(&ud_object, 64);
	ud_set_syntax(&ud_object, UD_SYN_ATT);
	while (ud_disassemble(&ud_object)) {
		printf("\t%s\n", ud_insn_asm(&ud_object));
	}
	printf("\n");
}

int main(int argc,  char **argv, char **envp)
{
	if (argc < 3) {
		printf("Usage: %s <program> <function>\n", argv[0]);
		exit(0);
	}
	char *args[2];
	args[0] = strdup(argv[1]);
	args[1] = NULL;
	Elf64_Parser elf_parser;
	bool ret = elf_parser.load_elf_file_to_mem(argv[1]);
	if (!ret) {
		printf("load elf file error!\n");
		exit(0);
	}
	Elf64_Addr sym_addr = elf_parser.lookup_symbol(argv[2]);
	if (!sym_addr) {
		printf("lookup_symbol %s error\n", argv[2]);
		return 0;
	}
	printf("symaddr: %016lx\n", sym_addr);
	int pid = 0;
	int status = 0;
	long trap, orig;
	struct user_regs_struct pt_reg;
	if ((pid = fork()) < 0) {
		perror("fork");
		exit(-1);
	}
	if (pid == 0) {
		/* child process */
		//表明子进程会被父进程跟踪
		if (ptrace(PTRACE_TRACEME, pid, NULL, NULL) < 0) {
			perror("PTRACE_TRACEME");
			exit(-1);
		}
		//执行子进程程序
		execve(args[0], args, envp);
		exit(0);
	}
	/* parent process */
	wait(&status);
	printf("Begining analysis of pid: %d at %lx\n", pid, sym_addr);
	//读取子进程（被追踪进程）的进程镜像虚拟内存地址
	if ((orig = ptrace(PTRACE_PEEKTEXT, pid, sym_addr, NULL)) == -1) {
		perror("PTRACE_PEEKTEXT");
		exit(-1);
	}
	printf("orig: %lx\n", orig);
	show_asm_instruction(orig);
	trap = (orig & ~0xff) | 0xcc; //int3指令的机器码
	printf("trap: %lx\n", trap);
	show_asm_instruction(trap);
	if (ptrace(PTRACE_POKETEXT, pid, sym_addr, trap) == -1) {
		perror("PTRACE_POKETEXT");
		exit(-1);
	}
trace:
	if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
		perror("PTRACE_CONT");
		exit(-1);
	}
	wait(&status);
	if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
		if (ptrace(PTRACE_GETREGS, pid, NULL, &pt_reg) == -1) {
			perror("PTRACE_GETREGS");
			exit(-1);
		}
		printf("\nExecutable %s (pid: %d) has hit breakpoint 0x%lx\n", argv[1], pid, sym_addr);
		printf("%%rcx: %llx\n"
			"%%rdx: %llx\n"
			"%%rbx: %llx\n"
			"%%rax: %llx\n"
			"%%rdi: %llx\n"
			"%%rsi: %llx\n"
			"%%r8: %llx\n"
			"%%r9: %llx\n"
			"%%r10: %llx\n"
			"%%r11: %llx\n"
			"%%r12: %llx\n"
			"%%r13: %llx\n"
			"%%r14: %llx\n"
			"%%r15: %llx\n"
			"%%rsp: %llx\n", pt_reg.rcx, pt_reg.rdx, pt_reg.rbx,
			pt_reg.rax, pt_reg.rdi, pt_reg.rsi,
			pt_reg.r8, pt_reg.r9, pt_reg.r10,
			pt_reg.r11, pt_reg.r12, pt_reg.r13,
			pt_reg.r14, pt_reg.r15, pt_reg.rsp);
		printf("\nPlease hit any key to continue: ");
		getchar();
		//回到int3指令处，重新恢复原有指令，执行正常逻辑
		if (ptrace(PTRACE_POKETEXT, pid, sym_addr, orig) == -1) {
			perror("PTRACE_POKETEXT");
			exit(-1);
		}
		pt_reg.rip = pt_reg.rip - 1;
		if (ptrace(PTRACE_SETREGS, pid, NULL, &pt_reg) == -1) {
			perror("PTRACE_SETREGS");
			exit(-1);
		}
		if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) {
			perror("PTRACE_SINGLESTEP");
			exit(-1);
		}
		wait(NULL);
		if (ptrace(PTRACE_POKETEXT, pid, sym_addr, trap) == -1) {
			perror("PTRACE_POKETEXT");
			exit(-1);
		}
		goto trace;
	}
	if (WIFEXITED(status)) {
		printf("Completed tracing pid: %d\n", pid);
	}
	return 0;

}

