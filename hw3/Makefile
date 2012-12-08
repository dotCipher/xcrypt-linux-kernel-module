# Makefile for HW3
# by: Cody Moore
# CSE 306

# Module rule
obj-m += sys_xcrypt.o

#### MAIN RULES ####
all: xcipher xcrypt

xcipher: xcipher.c
	gcc -Wall -Werror -I/lib/modules/$(shell uname -r)/build/arch/x86/include xcipher.c -o xcipher -lssl

xcrypt:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

#### DEBUG RULES ####
debug: xcrypt_dbg xcipher_dbg

xcipher_dbg: xcipher.c
	gcc -g -Wall -Werror -I/lib/modules/$(shell uname -r)/build/arch/x86/include xcipher.c -o xcipher_dbg -lssl

xcrypt_dbg:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

#### CLEAN RULE ####
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean; \
	rm -f xcipher
