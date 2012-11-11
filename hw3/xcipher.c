#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#define __NR_xcrypt	349	/* our private syscall number */

int main(int argc, char *argv[])
{
	int rc;
	void *dummy = (void *) atoi(argv[1]);

  	rc = syscall(__NR_xcrypt, dummy);
	if (rc == 0)
		printf("syscall returned %d\n", rc);
	else
		printf("syscall returned %d (errno=%d)\n", rc, errno);

	exit(rc);
}
