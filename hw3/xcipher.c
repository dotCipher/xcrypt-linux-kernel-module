#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "sys_xcrypt.h"

#define __NR_xcrypt	349	/* our private syscall number */

int main(int argc, char *argv[])
{
	int xcrypt_rv;
    struct xcrypt_params *params;
	void *param_ptr;
	
	params->infile = malloc(sizeof(char)*256);
	//params->infile = memset(0);
	params->infile = argv[1];
	param_ptr = (void *) params;
	
	printf("Test return: %s\n", params->infile);
	
  	//xcrypt_rv = syscall(__NR_xcrypt, param_ptr);
	//printf("system call returned with %d\n", xcrypt_rv);
	
	//free(params->infile);
	exit(xcrypt_rv);
}
