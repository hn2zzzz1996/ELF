#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>

#define BASE_ADR 0x100000
static inline volatile void *evil_mmap(void *addr, size_t len,
	int prot, int flags, int fd, off_t offset)
{
	long mmap_fd = fd;
	unsigned long mmap_off = offset;
	unsigned long mmap_flags = flags;
	unsigned long ret;
	__asm__ __volatile__(
		"mov %0, %%rdi\n"
		"mov %1, %%rsi\n"
		"mov %2, %%rdx\n"
		"mov %3, %%r10\n"
		"mov %4, %%r8\n"
		"mov %5, %%r9\n"
		"mov $9, %%rax\n"
		"syscall\n"
		: : "g"(addr), "g"(len), "g"(prot), "g"(flags),
		"g"(mmap_fd), "g"(mmap_off)
		);
	asm ("mov %%rax, %0" : "=r"(ret));
	return (void *)ret;
}


int main(){
	void *mem = evil_mmap((void*)BASE_ADR, 8192, 
		PROT_READ | PROT_WRITE | PROT_EXEC,
		MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
	if(mem == MAP_FAILED){
		perror("mmap");
		exit(-1);
	}
	char *s = mem;
	s[0] = 'h';
	s[1] = 's';
	s[2] = '\0';
	printf("%s\n", s);
}
