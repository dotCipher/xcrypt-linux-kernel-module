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
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/file.h>

#include "common.h"

struct file* kfile_open(const char* path, int flags, int permissions){
	struct file* filp = NULL;
	mm_segment_t oldfs;
	int error = 0;
	
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

int kfile_unlink(struct file* file){
	int ret;
	ret = vfs_unlink();
	
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

asmlinkage extern long (*sysptr)(void *arg);

asmlinkage int sys_xcrypt(void *args){
	// Declare the needed variables
	void *k_args;
	char *k_infile;
	char *k_outfile;
	char *k_keybuf;
	int k_keylen;
	unsigned char k_flags;
	long page_size;
	char *buffer;
	struct file *infile;
	struct file *outfile;
	long long bytes_read, bytes_write;
	int params_len = sizeof(struct xcrypt_params);
	page_size = 4096;
	printk(KERN_CRIT "--- Entering kerning module sys_xcrypt ---\n");
	
	// Check if the void pointer is from userspace is readable
	if(!access_ok(VERIFY_READ, args, params_len)){
		return -EFAULT;
	}
	// Alloc memory for void pointer
	if(!(k_args = kmalloc(params_len, GFP_KERNEL))){
		return -ENOMEM;
	}
	if(copy_from_user(k_args, args, params_len)){
		kfree(k_args);
		return -EINVAL;
	}
	
	// Alloc memory and retrive data
	// Keylen
	if(!access_ok(VERIFY_READ, ((struct xcrypt_params *)k_args)->keylen,
	sizeof(int))){
		printk(KERN_CRIT "Kernel cant read keylength");
		kfree(k_args);
		return -EFAULT;
	}
	k_keylen = (((struct xcrypt_params *)k_args)->keylen);
	
	// Keybuf
	if(!(k_keybuf = kmalloc(((struct xcrypt_params *)k_args)->keylen, 
	GFP_KERNEL))){
		kfree(k_args);
		return -ENOMEM;
	}
	if(!access_ok(VERIFY_READ, ((struct xcrypt_params *)k_args)->keybuf,
	((struct xcrypt_params *)k_args)->keylen)){
		kfree(k_args); kfree(k_keybuf);
		return -EFAULT;
	}
	if(copy_from_user(k_keybuf, ((struct xcrypt_params *)k_args)->keybuf,
	((struct xcrypt_params *)k_args)->keylen)){
		kfree(k_args); kfree(k_keybuf);
		return -EINVAL;
	}
	
	// Flags
	if(!access_ok(VERIFY_READ, ((struct xcrypt_params *)k_args)->flags,
	sizeof(unsigned char))){
		printk(KERN_CRIT "Kernel cant read flags");
		kfree(k_args); kfree(k_keybuf);
		return -EFAULT;
	}
	k_flags = ((struct xcrypt_params *)k_args)->flags;
		
	// Infile and outfile 
	k_infile = getname(((struct xcrypt_params *)k_args)->infile);
	k_outfile = getname(((struct xcrypt_params *)k_args)->outfile);
	
	// Debug messages
	printk(KERN_CRIT "k_infile = %s\n", k_infile);
	printk(KERN_CRIT "k_outfile = %s\n", k_outfile);
	printk(KERN_CRIT "k_keybuf = %s\n", k_keybuf);
	printk(KERN_CRIT "k_keylen = %d\n", k_keylen);
	printk(KERN_CRIT "k_flags = %d\n", k_flags);
	
	// Error check both the infile and outfile
	
	// Clear buffer
	if(!(buffer = kmalloc(page_size, GFP_KERNEL))){
		kfree(k_args); kfree(k_keybuf);
		kfree(k_infile); kfree(k_outfile);
		return -ENOMEM;
	}	

	memset(buffer, 0, page_size);
		
	// Open the infile 
	if((infile = kfile_open(k_infile, O_RDONLY, S_IRUSR)) == NULL){
		kfree(k_args); kfree(k_keybuf);
		kfree(k_infile); kfree(k_outfile);
		return -EINVAL;
	}
	
	/* --- Main I/O loop --- */
	bytes_read = -1;
	while(bytes_read != 0){
		bytes_read = kfile_read(infile, bytes_read, buffer, page_size);
		if(bytes_read == -1){
			// Partial read encountered
			kfree(k_args); kfree(k_keybuf);
			kfree(k_infile); kfree(k_outfile);
			// Close file
			kfile_close(infile);
			return -EINVAL;
		} else if(bytes_read > 0){
			// Was read even with page_size?
			if(bytes_read == page_size){
				// page_size has been read
				// Encrypt/Decrypt buffer
				
				// Write buffer
				bytes_write = kfile_write(outfile, bytes_read, 
				buffer, page_size);
				
				if(bytes_write == -1){
					// Partial write encountered?
					kfree(k_args); kfree(k_keybuf);
					kfree(k_infile); kfree(k_outfile);
					// Close file
					kfile_close(infile);
					return -EINVAL;
				}
			 } else if(bytes_read < page_size){
			 	// bytes_read has been read
			 	// Encrypt/Decrypt buffer
			 	
			 	// Write buffer
			 	bytes_write = kfile_write(outfile, bytes_read, 
			 	buffer, bytes_read);
			 	
			 	if(bytes_write == -1){
			 		// Partial write encountered?
					kfree(k_args); kfree(k_keybuf);
					kfree(k_infile); kfree(k_outfile);
					// Close file
					kfile_close(infile);
					return -EINVAL;
			 	}
			 }
			 // Clear buffers
			 memset(to_buffer, 0, page_size);
			 memset(from_buffer, 0, page_size);
		} // else bytes_read == 0, terminate while
	}
	
	
	kfree(k_args); kfree(k_keybuf);
	kfree(k_infile); kfree(k_outfile);
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
