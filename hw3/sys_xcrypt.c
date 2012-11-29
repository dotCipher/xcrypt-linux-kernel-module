#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/fcntl.h>
#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>

#include <asm/uaccess.h>
#include <asm/segment.h>

#include "sys_xcrypt.h"

struct file* kfile_open(const char* path, int flags, int permissions){
	struct file* filp = NULL;
	mm_segment_t oldfs;
	int error =0;
	
	oldfs = get_fs();
	set_fs(get_ds());
	filp = filp_open(path, flags, permissions);
	set_fs(oldfs);
	if(IS_ERR(filp)){
		error = PTR_ERR(filp);
		return NULL;
	}
	return filp;
}

void kfile_close(struct file* file){
	filp_close(file, NULL);
}

int kfile_read(struct file* file, unsigned long offset, unsigned char* 
data, unsigned int size){
	mm_segment_t oldfs;
	int ret;
	
	oldfs = get_fs();
	set_fs(get_ds());
	
	ret = vfs_read(file, data, size, &offset);
	
	set_fs(oldfs);
	return ret;
}

int kfile_write(struct file* file, unsigned long offset, unsigned char* 
data, unsigned int size){
	mm_segment_t oldfs;
	int ret;
	
	oldfs = get_fs();
	set_fs(get_ds());
	
	ret = vfs_write(file, data, size, &offset);
	
	set_fs(oldfs);
	return ret;
}

int kfile_sync(struct file* file){
	vfs_fsync(file, 0);
	return 0;
}

asmlinkage extern long (*sysptr)(void *arg);

asmlinkage int sys_xcrypt(void *args){
	/*
	sys_xcrypt(infile, outfile, keybuf, keylen, flags)
	where "infile" is the name of an input file to encrypt or decrypt, "outfile"
	is the output file, "keybuf" is a buffer holding the cipher key, "keylen" is
	the length of that buffer, and "flags" determine if you're encrypting or
	decrypting.
	*/
	/* Both input and output files can be passed as relative or absolute */
	/* ERRORS TO CHECK FOR */
	/*
	- missing arguments passed
	- null arguments
	- pointers to bad addresses
	- len and buf don't match
	- invalid flags
	- input file cannot be opened or read
	- output file cannot be opened or written
	- input or output files are not regular, or they point to the same file
	- trying to decrypt a file w/ the wrong key (what errno should you return?)
	- ANYTHING else you can think of (the more error checking you do, the better)
	*/
	
	// Declare the needed variables
	//int fd;
	//int error;
	//char *buf;
	//mm_segment_t old_fs;
	/*
	char *k_infile;
	char *k_outfile;
	char *k_keybuf;
	int k_keylen;
	unsigned char k_flags;
	*/
	
	// Initialize starter variables
	//old_fs = get_fs();
	//set_fs(KERNEL_DS);
	
	// First dereference the void pointer to our struct
	struct xcrypt_params *params = (struct xcrypt_params *)args;
	
	// Check the infile
	// access_ok(type, addr, size)
	// __strncpy_from_user(dst, src, count)
	return access_ok(VERIFY_READ, args, sizeof(*args));
	//if(access_ok(VERIFY_READ, params->infile, strnlen_user(params->infile, (long)256))){
		
	//}
	
	// Check the outfile
	
	// Check the keybuf
	
	// Check the keylen
	
	// Check the flags
	
}

static int __init init_sys_xcrypt(void){
	printk("installed new sys_xcrypt module\n");
	if (sysptr == NULL)
		sysptr = sys_xcrypt;
	return 0;
}
static void  __exit exit_sys_xcrypt(void){
	if (sysptr != NULL)
		sysptr = NULL;
	printk("removed sys_xcrypt module\n");
}
module_init(init_sys_xcrypt);
module_exit(exit_sys_xcrypt);
MODULE_LICENSE("GPL");
