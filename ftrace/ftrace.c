#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/ptrace.h>

#define CALLSTACK_DEPTH 1000000
#define MAX_SHDRS 256

struct {
	int arch;
	int showret;
	int verbose;
} opts;

struct elf64{
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	Elf64_Sym  *sym;
	Elf64_Dyn  *dyn;

	char *StringTable;
	char *SymStringTable;
};

struct elf32{
	Elf32_Ehdr *ehdr;
	Elf32_Phdr *phdr;
	Elf32_Shdr *shdr;
	Elf32_Sym  *sym;
	Elf32_Dyn  *dyn;

	char *StringTable;
	char *SymStringTable;
};

struct address_space{
	unsigned long svaddr;
	unsigned long evaddr;
	unsigned int size;
	int count;
};

struct syms {
	char *name;
	unsigned long value;
};

typedef struct breakpoint{
	unsigned long vaddr;
	long orig_code;
} breakpoint_t;

typedef struct calldata{
	char *symname;
	char *string;
	unsigned long vaddr;
	unsigned long retaddr;
	breakpoint_t breakpoint;
} calldata_t;

typedef struct callstack{
	/* use array to simulate stack */
	calldata_t *calldata;
	unsigned int depth;
} callstack_t;

struct handle{
	char *path;

};

int global_pid;

void * HeapAlloc(unsigned int size);

void set_breakpoint(callstack_t *callstack){
	long orig = ptrace(PTRACE_PEEKTEXT, global_pid, callstack->calldata[callstack->depth].retaddr);
	long trap;

	trap = (orig & ~0xff) | 0xcc;
	if(opts.verbose)
		printf("[+] Setting breakpoint on 0x%lx\n", callstack->calldata[callstack->depth].retaddr);

	ptrace(PTRACE_POKETEXT, global_pid, callstack->calldata[callstack->depth].retaddr, trap);
	callstack->calldata[callstack->depth].breakpoint.orig_code = orig;
	callstack->calldata[callstack->depth].breakpoint.vaddr = callstack->calldata[callstack->depth].retaddr;
}

void remove_breakpoint(callstack_t *callstack){
	if(opts.verbose)
		printf("[+] Removing breakpoint on 0x%lx\n", callstack->calldata[callstack->depth].retaddr);

	ptrace(PTRACE_POKETEXT, global_pid, callstack->calldata[callstack->depth].retaddr,
		callstack->calldata[callstack->depth].breakpoint.orig_code);
}

/*
 * Simple array implementation of stack
 * to keep track of function depth and return values
 */
void callstack_init(callstack_t *callstack){
	callstack->calldata = HeapAlloc(sizeof(*callstack->calldata) * CALLSTACK_DEPTH);
	callstack->depth = -1;
}

void callstack_push(callstack_t *callstack, calldata_t *calldata){
	memcpy(&callstack->calldata[++callstack->depth], calldata, sizeof(calldata_t));
	set_breakpoint(callstack);
}

calldata_t * callstack_pop(callstack_t *callstack){
	if(callstack->depth == -1)
		return NULL;

	remove_breakpoint(callstack);
	return (&callstack->calldata[callstack->depth--]);
}

calldata_t * callstack_peen(callstack_t *callstack){
	if(callstack->depth == -1)
		return NULL;

	return (&callstack->calldata[callstack->depth]);
}

void * HeapAlloc(unsigned int size){
	void *mem = malloc(size);
	if(!mem){
		perror("malloc");
		exit(-1);
	}
	return mem;
}

char *xstrdup(const char *s){
	char *p = strdup(s);
	if(p == NULL){
		perror("strdup");
		exit(-1);
	}
	return p;
}

/*
 * ptrace function
 */

int pid_read(int pid, void *dst, void *src, size_t len){
	int sz = len / sizeof(void *);
	char *s = (char *)src;
	char *d = (char *)dst;
	
	long word;
	while(sz-- > 0){
		word = ptrace(PTRACE_PEEKTEXT, pid, src, NULL);
		if(word == -1 && errno){
			perror("ptrace in pid_read");
			return -1;
		}

		*(long *)d = word;
		s += sizeof(void *);
		d += sizeof(void *);
	}
	return 0;
}

/*
 * Get global/local and dynamic
 * symbol/function information.
 */
int BuildSyms(struct handle *h){
	
}

void sighandler(int sig){
	fprintf(stdout, "Caught signal ctrl-C, detaching...\n");
	exit(0);
}

int main(int argc, char *argv[]){
	
	struct sigaction sig;
	sigset_t set;
	sig.sa_handler = sighandler;
	sigemptyset(&sig.sa_mask);
	sig.sa_flags = 0;
	sigaction(SIGINT, &sig, NULL);
	sigemptyset(&set);
	sigaddset(&set, SIGINT);

	if(argc < 2){
	usage:
		printf("Usage: \n");
	}
}
