#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <elf.h>

#define RED "\x1B[31m"

struct handle{
	char *mem;
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
};
struct handle *h;

void mapElf64(char *file){
	int fd;
	struct stat st;

	if((fd = open(file, O_RDONLY)) < 0){
		fprintf(stderr, "Unable to open %s: %s\n", file, strerror(errno));
		exit(-1);
	}

	if(fstat(fd, &st) < 0){
		perror("fstat");
		exit(-1);
	}

	h->mem = (char *)mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if(h->mem == MAP_FAILED){
		perror("mmap");
		exit(-1);
	}

	h->ehdr = (Elf64_Ehdr *)h->mem;
	h->phdr = (Elf64_Phdr *)(h->mem + h->ehdr->e_phoff);
	h->shdr = (Elf64_Shdr *)(h->mem + h->ehdr->e_shoff);
}

void showSym(){
	unsigned int i, j, k;
	char *SymStrTable;
	Elf64_Ehdr *ehdr;
	Elf64_Shdr *shdr;
	Elf64_Sym *symtab;
	int st_type;

	ehdr = h->ehdr;
	shdr = h->shdr;

	for(i = 0; i < ehdr->e_shnum; i++){
		if(shdr[i].sh_type == SHT_SYMTAB || shdr[i].sh_type == SHT_DYNSYM){
			SymStrTable = (char *)&h->mem[shdr[shdr[i].sh_link].sh_offset];
			symtab = (Elf64_Sym *)&h->mem[shdr[i].sh_offset];

			for(j = 0; j < shdr[i].sh_size / sizeof(Elf64_Sym); j++, symtab++){
				st_type = ELF64_ST_TYPE(symtab->st_info);
				if(st_type != STT_FUNC)
					continue;

				switch(shdr[i].sh_type){
					case SHT_SYMTAB:
						printf("%sSYMTAB: Symname: %s, Symvalue: 0x%lx\n", 
							RED,&SymStrTable[symtab->st_name], symtab->st_value);
						break;
					/* Initial value should point to the .plt */
					case SHT_DYNSYM:
						printf("DYNSYM: Symname: %s, Symvalue: 0x%lx\n", 
								&SymStrTable[symtab->st_name], symtab->st_value);
						break;
				}
			}
		}
	}
}

int main(int argc, char *argv[]){
	h = malloc(sizeof(struct handle));
	mapElf64(strdup(argv[1]));
	showSym();
	free(h);
}
