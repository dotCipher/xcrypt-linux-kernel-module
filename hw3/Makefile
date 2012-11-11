obj-m += sys_xcrypt.o

all: xcipher xcrypt

xcipher: xcipher.c
	gcc -Wall -Werror -I/lib/modules/$(shell uname -r)/build/arch/x86/include xcipher.c -o xcipher -lssl

xcrypt:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f xcipher
