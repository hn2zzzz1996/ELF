#include <stdio.h>
#include <unistd.h>

int main(){
	printf("My pid is %d, Please inject me!\n", getpid());
	while(1);
}
