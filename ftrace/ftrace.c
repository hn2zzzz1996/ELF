/* Incomplete, just reference */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/reg.h>

/*
 * For color coding output
 */
#define WHITE "\x1B[37m"
#define RED "\x1B[31m"
#define GREEN "\x1B[32m"
#define YELLOW "\x1B[33m"
#define DEFAULT_COLOR "\x1B[0m"

#define FTRACE_ENV "FTRACE_ARCH"

#define MAX_SYMS 8192 * 2

#define CALLSTACK_DEPTH 1000000
#define MAX_SHDRS 256

struct {
	int arch;
	int showret;
	int verbose;
	int attach;
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
	char **args;
	char *mem;
	struct elf32 *elf32;
	struct elf64 *elf64;
	struct syms lsyms[MAX_SYMS]; //local syms
	struct syms dsyms[MAX_SYMS]; //dynamic syms
	char *libnames[256];
	int lsc;	//lsyms count
	int dsc;	//dsyms count
	int lnc;	//libnames count
	int shdr_count;
	int pid;
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

calldata_t * callstack_peek(callstack_t *callstack){
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
 * Main handler
 */
void examine_process(struct handle *h){
	int i, status, eip;
	struct user_regs_struct regs;

	callstack_t callstack;
	calldata_t calldata;
	calldata_t *calldp;

	BuildSyms(h);

	callstack_init(&callstack);
	
	for(;;){
		ptrace(PTRACE_SINGLESTEP, h->pid, NULL, NULL);
		wait(&status);

		if(WIFEXITED(status))
			break;

		ptrace(PTRACE_GETREGS, h->pid, NULL, &regs);

		eip = regs.eip;

		if(pid_read(h->pid, buf, eip, 8) < 0){
			perror("pid_read");
			exit(-1);
		}

		if(buf[0] == 0xcc){
			calldp = callstack_peek(&callstack);
			if(calldp != NULL){
				if(calldp->retaddr == eip){
					
					calldp = callstack_pop(&callstack);
				}
			}
		}
	
		if(buf[0] == 0xe8){
			offset = buf[1]	+ (buf[2] << 8) + (buf[3] << 16) + (buf[4] << 24);
			vaddr = eip + offset + 5;
			vaddr &= 0xffffffff;

			for(i = 0; i < h->lsc; i++){
				if(vaddr == h->lsyms[i].value){
					printf("%sLOCAL_call@0x%lx:%s%s()\n", GREEN, h->lsyms[i].name, 
						WHITE, h->lsyms[i].name ? h->lsyms[i].name : "<unknown>");

					calldata.vaddr = h->lsyms[i].value;
					calldata.retaddr = eip + 5;
					callstack_push(&callstack, &calldata);
				}
			}
		}
	}
}

/*
 * Get global/local and dynamic
 * symbol/function information.
 */
int BuildSyms(struct handle *h){
	int i, j, k;
	Elf64_Ehdr *ehdr64;
	Elf64_Shdr *shdr64;
	Elf64_Sym  *symtab64;
	char *SymStrTable;
	int st_type;

	h->lsc = 0;
	h->dsc = 0;

	switch(opts.arch){
		case 32:
			break;
		case 64:
			ehdr64 = h->elf64->ehdr;
			shdr64 = h->elf64->shdr;
			for(i = 0; i < ehdr64->e_shnum; i++){
				if(shdr64[i].sh_type == SHT_SYMTAB || shdr64[i].sh_type == SHT_DYNSYM){
					SymStrTable = (char *)&h->mem[shdr64[shdr64[i].sh_link].sh_offset];
					symtab64 = (Elf64_Sym *)&h->mem[shdr64[i].sh_offset];

					for(j = 0; j < shdr64[i].sh_size / sizeof(Elf64_Sym); j++, symtab64++){
						st_type = ELF64_ST_TYPE(symtab64->st_info);
						if(st_type != STT_FUNC)
							continue;

						switch(shdr64[i].sh_type){
							case SHT_SYMTAB:
								h->lsyms[h->lsc].name = xstrdup(&SymStrTable[symtab64->st_name]);
								h->lsyms[h->lsc].value = symtab64->st_value;
								h->lsc++;
								break;
							case SHT_DYNSYM:
								h->dsyms[h->dsc].name = xstrdup(&SymStrTable[symtab64->st_name]);
								h->dsyms[h->dsc].value = symtab64->st_value;
								h->dsc++;
								break;
						}
					}
				}
			}

			h->elf64->StringTable = &h->mem[shdr64[ehdr64->e_shstrndx].sh_offset];
			for(i = 0; i < ehdr64->e_shnum; i++){
				if(!strcmp(&h->elf64->StringTable[shdr64[i].sh_name], ".plt")){
					for(j = 0, k = 0; j < shdr64[i].sh_size; j += 16){
						/* first plt is used for opcode */
						if(j >= 16){
							h->dsyms[k++].value = shdr64[i].sh_addr + j;
						}
					}
					break;
				}
			}
			break;
	}
	return 0;
}

void PrintSyms(struct handle *h){
	int i;
	for(i = 0; i < h->lsc; i++){
		printf("LSyms: %s, Value: 0x%lx\n", h->lsyms[i].name, h->lsyms[i].value);
	}
	for(i = 0; i < h->dsc; i++){
		printf("DSyms: %s, Value: 0x%lx\n", h->dsyms[i].name, h->dsyms[i].value);
	}
}

void MapElf64(struct handle *h){
	int fd;
	struct stat st;

	if((fd = open(h->path, O_RDONLY)) < 0){
		fprintf(stderr, "Can't open %s\n", h->path);
		exit(-1);
	}

	if(fstat(fd, &st) < 0){
		perror("fstat");
		exit(-1);
	}

	h->mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if(h->mem == MAP_FAILED){
		perror("mmap");
		exit(-1);
	}

	h->elf64 = HeapAlloc(sizeof(struct elf64));

	h->elf64->ehdr = (Elf64_Ehdr *)h->mem;
	h->elf64->phdr = (Elf64_Phdr *)(h->mem + h->elf64->ehdr->e_phoff);
	h->elf64->shdr = (Elf64_Shdr *)(h->mem + h->elf64->ehdr->e_shoff);
}

void sighandler(int sig){
	fprintf(stdout, "Caught signal ctrl-C, detaching...\n");
	exit(0);
}

int main(int argc, char *argv[], char **envp){
	int pid, status, i, opt, skip_getopt = 0;
	struct handle h;
	char *arch, **p;

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
		printf("Usage: %s [-Sstve] <prog>\n", argv[0]);
		exit(0);
	}

	if(argc == 2 && argv[1][0] == '-')
		goto usage;

	memset(&opts, 0, sizeof(opts));

	opts.arch = 64;
	arch = getenv(FTRACE_ENV);
	if(arch != NULL){
		switch(atoi(arch)){
			case 32:
				break;
			case 64:
				opts.arch = 64;
				break;
			default:
				fprintf(stderr, "Unknown architecture: %s\n", arch);
				break;
		}
	}
	
	if(!opts.attach){
		if(!validate_em_type(h.path)){
			printf("[!] ELF Architecture is set to %d, the target %s is not the same architecture\n", 
					opts.arch, h.path);
		}

		if((pid = fork()) < 0){
			perror("fork");
			exit(-1);
		}
		if(pid == 0){
			if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1){
				perror("PTRACE_TRACEME");
				exit(-1);
			}
			
		}
	}
}
