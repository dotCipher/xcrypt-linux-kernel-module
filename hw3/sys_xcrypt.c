#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fcntl.h>
#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/slab.h>

#include <asm/uaccess.h>
#include <asm/segment.h>

#include "common.h"

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

int kfile_read(struct file* file, unsigned long long offset, unsigned char* 
data, unsigned int size){
	mm_segment_t oldfs;
	int ret;
	
	oldfs = get_fs();
	set_fs(get_ds());
	
	ret = vfs_read(file, data, size, &offset);
	
	set_fs(oldfs);
	return ret;
}

int kfile_write(struct file* file, unsigned long long offset, unsigned char* 
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

// -1 = Failure   0 = Success
int kmem_alloc_params(struct xcrypt_params *ptr){
	ptr = kmalloc(sizeof(struct xcrypt_params), GFP_KERNEL);
	if(!ptr){
		return -1;
	} else {
		return 0;
	}
	ptr->infile = kmalloc(INFILE_MAX, GFP_KERNEL);
	if(!ptr->infile){
		return -1;
	} else {
		return 0;
	}
	ptr->outfile = kmalloc(OUTFILE_MAX, GFP_KERNEL);
	if(!ptr->outfile){
		return -1;
	} else {
		return 0;
	}
	ptr->keybuf = kmalloc(PASS_MAX, GFP_KERNEL);
	if(!ptr->keybuf){
		return -1;
	} else {
		return 0;
	}
}

asmlinkage extern long (*sysptr)(void *arg);

asmlinkage int sys_xcrypt(void *args){
	// Declare the needed variables
	char *k_infile;
	char *k_outfile;
	char *k_keybuf;
	int k_keylen;
	unsigned char k_flags;
	
	// Check if the void pointer is from userspace is readable
	if(!access_ok(VERIFY_READ, args, sizeof(args))){
		return -EFAULT;
	}
	// Alloc memory for the parts of the struct 
	//   that the void pointer is pointing too
	k_infile = getname( ((struct xcrypt_params *)args)->infile );

	return 0;
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
