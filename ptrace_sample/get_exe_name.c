#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

char* get_exe_name(int pid){
	char cmdline[255], path[512], *p;
	int fd;
	sprintf(cmdline, "/proc/%d/cmdline", pid);
	if((fd = open(cmdline, O_RDONLY)) < 0){
		perror("open");
		exit(-1);
	}
	if(read(fd, path, 512) < 0){
		perror("read");
		exit(-1);
	}
	if((p = strdup(path)) == NULL){
		perror("strdup");
		exit(-1);
	}
	return p;
}

int main(int argc, char *argv[]){
	int pid;
	if(argc < 2){
		printf("Usage: %s <pid>\n", argv[0]);
		exit(0);
	}
	pid = atoi(argv[1]);
	printf("%s\n", get_exe_name(pid));
}
