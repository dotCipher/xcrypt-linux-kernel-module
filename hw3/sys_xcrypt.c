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
#include <linux/crypto.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <linux/namei.h>

#include "common.h"

static const u8 *iv_str = (u8 *)"x8QR55HKpW52464q";

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


int kfile_unlink(struct file *file, char *path, int len){
	int ret;
	struct dentry *dentry, *rdentry;
	struct inode *dirptr;
	dentry = file->f_dentry;
	dirptr = dentry->d_inode;
	rdentry = lookup_one_len(path, dentry, len);
	ret = vfs_unlink(dirptr, rdentry);
	return ret;
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

int is_same_kfile(struct file* file1, struct file* file2){
	if(file1->f_dentry->d_inode->i_ino == file2->f_dentry->d_inode->i_ino 
	&& file1->f_dentry->d_sb == file2->f_dentry->d_sb){
		return 1;
	} else {
		return 0;
	}
}

static struct crypto_blkcipher *xcrypt_alloc_tfm(void){
	return crypto_alloc_blkcipher("cbc(aes)", 0, CRYPTO_ALG_ASYNC);
}

int xencrypt_buffer(void *key, int keylen, 
char *to_buffer, size_t *to_len,
char *from_buffer, size_t from_len, short pgflag){
	// Declare all needed variables
	struct scatterlist src[2];
	struct scatterlist dst[1];
	struct crypto_blkcipher *tfm = xcrypt_alloc_tfm();
	int ret, i;
	void *iv;
	int ivsize;
	size_t zero_pad;
	char pad[16];
	struct blkcipher_desc desc = {
		.tfm = tfm, .flags = 0 };
	ret = 1; i = 0;
	
	if(IS_ERR(tfm)){
		ret = PTR_ERR(tfm);
		printk(KERN_CRIT "Cant load transform\n");
		crypto_free_blkcipher(tfm);
		return ret;
	}
	//printk(KERN_CRIT "Setting crypto cipher key\n");
	
	// Force padding if above page size
	if(pgflag != 1){
		zero_pad = 	(0x10 - (from_len & 0x0f));
		memset(pad, zero_pad, zero_pad);
		*to_len = from_len + zero_pad;
	} else {
		zero_pad = 0;
	}
	
	//printk(KERN_CRIT "key = %s\n", key);
	crypto_blkcipher_setkey((void *)tfm, key, keylen);

	sg_init_table(src, 2);
	sg_set_buf(&src[0], from_buffer, from_len);
	if(pgflag != 1){
		sg_set_buf(&src[1], pad, zero_pad);
	}
	sg_init_table(dst, 1);
	sg_set_buf(&dst[0], to_buffer, *to_len);
	
	// Set Initialization Vector
	//printk(KERN_CRIT "Setting iv.\n");
	iv = crypto_blkcipher_crt(tfm)->iv;
	ivsize = crypto_blkcipher_ivsize(tfm);
	//printk(KERN_CRIT "ivsize = %d\n", ivsize);
	
	// TODO: Change this to allow new ivs
	memcpy(iv, iv_str, ivsize);
	//printk(KERN_CRIT "iv = %s\n", (unsigned char *)iv);

	//printk(KERN_CRIT "Encrypting in xcrypt_cipher()\n");
	ret = crypto_blkcipher_encrypt(&desc, dst, src, from_len + zero_pad);
	crypto_free_blkcipher(tfm);
	//kfree(new_key);
	
	if(ret < 0){
		printk(KERN_CRIT "Encryption failed\n");
		return ret;
	}
	//printk(KERN_CRIT "Returning from xcrypt_cipher()\n");
	return 0;
}

int xdecrypt_buffer(void *key, int keylen, 
char *to_buffer, size_t *to_len,
char *from_buffer, size_t from_len, short pgflag){
	// Declare all needed variables
	struct scatterlist src[1];
	struct scatterlist dst[2];
	struct crypto_blkcipher *tfm = xcrypt_alloc_tfm();
	int ret, i, last_byte;
	void *iv;
	int ivsize;
	size_t zero_pad;
	char pad[16];
	struct blkcipher_desc desc = { .tfm = tfm };
	ret = 1; i = 0; last_byte = 0;
	
	if(IS_ERR(tfm)){
		ret = PTR_ERR(tfm);
		printk(KERN_CRIT "Cant load transform\n");
		crypto_free_blkcipher(tfm);
		return ret;
	}
	//printk(KERN_CRIT "Setting crypto cipher key\n");
	
	// Set padding
	if(pgflag != 1){
		zero_pad = (0x10 - (from_len & 0x0f));
		memset(pad, zero_pad, zero_pad);
		// *to_len = from_len - zero_pad;
	} else {
		zero_pad = 0;
	}               	
	crypto_blkcipher_setkey((void *)tfm, key, keylen);
	sg_init_table(src, 1);
	sg_set_buf(&src[0], from_buffer, from_len);
	sg_init_table(dst, 2);
	sg_set_buf(&dst[0], to_buffer, *to_len);
	if(pgflag != 1){
		sg_set_buf(&dst[1], pad, sizeof(pad));
	}
	
	// Set ivs
	//printk(KERN_CRIT "Setting iv.\n");
	iv = crypto_blkcipher_crt(tfm)->iv;
	ivsize = crypto_blkcipher_ivsize(tfm);
	//printk(KERN_CRIT "ivsize = %d\n", ivsize);
	
	// TODO: Change to allow new ivs
	memcpy(iv, iv_str, ivsize);
	//printk(KERN_CRIT "iv = %s\n", (unsigned char *)iv);
	
	//printk(KERN_CRIT "Decrypting in xcrypt_cipher()\n");
	//printk(KERN_CRIT "from_len = %d\n", from_len);
	if(pgflag != 1){
		ret = crypto_blkcipher_decrypt(&desc, dst, src, *to_len);
	} else {
		ret = crypto_blkcipher_decrypt(&desc, dst, src, from_len);
	}
	crypto_free_blkcipher(tfm);
	
	if(ret < 0){
		printk(KERN_CRIT "Decryption failed\n");
		return ret;
	}
	
	// Remove excess padding
	if(pgflag != 1){
		if(from_len <= *to_len){
			last_byte = ((char *)to_buffer)[from_len - 1];
		} else {
			last_byte = pad[from_len - *to_len - 1];
		}
		//printk(KERN_CRIT "--- last_byte = %d\n", last_byte);
		if(last_byte <= 16 && from_len >= last_byte){
			*to_len = from_len - last_byte;
		} else {
			ret = 1;
			printk(KERN_CRIT "Encountered bad padding on %d on src_len %d\n",
			last_byte, (int)from_len);
			return ret;
		}
	}
	
	///printk(KERN_CRIT "Returning from xcrypt_cipher()\n");
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
	int page_size;
	unsigned char *buffer;
	struct file *infile;
	struct file *outfile;
	long long bytes_read, bytes_write;
	size_t src_len;
	size_t *dst_len;
	int offset_total;
	int params_len = sizeof(struct xcrypt_params);
	int i = 0;
	page_size = PAGE_CACHE_SIZE;
	
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
		kfree(k_args);
		return -EFAULT;
	}
	k_keylen = (((struct xcrypt_params *)k_args)->keylen);
	
	// Keybuf
	if(!(k_keybuf = kmalloc(PASS_MAX, GFP_KERNEL))){
		kfree(k_args);
		return -ENOMEM;
	}
	if(!access_ok(VERIFY_READ, ((struct xcrypt_params *)k_args)->keybuf,
	k_keylen)){
		kfree(k_args); kfree(k_keybuf);
		return -EFAULT;
	}
	if(copy_from_user(k_keybuf, ((struct xcrypt_params *)k_args)->keybuf,
	PASS_MAX)){
		kfree(k_args); kfree(k_keybuf);
		return -EINVAL;
	}
	
	// Flags
	if(!access_ok(VERIFY_READ, ((struct xcrypt_params *)k_args)->flags,
	sizeof(unsigned char))){
		kfree(k_args); kfree(k_keybuf);
		return -EFAULT;
	}
	k_flags = ((struct xcrypt_params *)k_args)->flags;
		
	// Infile and outfile 
	k_infile = getname(((struct xcrypt_params *)k_args)->infile);
	k_outfile = getname(((struct xcrypt_params *)k_args)->outfile);
	
	// Debug messages
	/*
	printk(KERN_CRIT "k_infile = %s\n", k_infile);
	printk(KERN_CRIT "k_outfile = %s\n", k_outfile);
	printk(KERN_CRIT "k_keybuf = %s\n", k_keybuf);
	printk(KERN_CRIT "k_keylen = %d\n", k_keylen);
	printk(KERN_CRIT "k_flags = %d\n", k_flags);
	*/
	
	// Clear buffer
	if(!(buffer = (unsigned char *)kmalloc(page_size, GFP_KERNEL))){
		kfree(k_args); kfree(k_keybuf);
		kfree(k_infile); kfree(k_outfile);
		printk(KERN_CRIT "No memory for buffer \n");
		return -ENOMEM;
	}
	memset(buffer, 0, page_size);
	
	// Errror check both files
	
	// Open the infile 
	if((infile = kfile_open(k_infile, 
	O_RDONLY, S_IRUSR)) == NULL){
		kfree(k_args); kfree(k_keybuf);
		kfree(k_infile); kfree(k_outfile);
		kfree(buffer);
		return -EINVAL;
	}
	
	// Open the outfile
	if((outfile = kfile_open(k_outfile, 
	O_RDONLY | O_CREAT, S_IRUSR)) == NULL){		
		kfree(k_args); kfree(k_keybuf);
		kfree(k_infile); kfree(k_outfile);
		kfree(buffer);
		// Close infile
		kfile_close(infile); 
		return -EINVAL;
	}
	
	// Compare same file or links 
	//  (dentry->d_inode check and dentry->d_sb check)
	
	//  dentry->d_inode->i_size for removing pratial outfiles
	if(is_same_kfile(infile, outfile)){
		kfree(k_args); kfree(k_keybuf);
		kfree(k_infile); kfree(k_outfile);
		kfree(buffer); 
		// Close and unlink
		kfile_close(infile);
		kfile_close(outfile); 
		//kfile_unlink(outfile, k_outfile, strlen(k_outfile));
		return -EINVAL;
	} else {
		// Not the same file, re open outfile 
		kfile_close(outfile); 
		//kfile_unlink(outfile, k_outfile, strlen(k_outfile));
		if((outfile = kfile_open(k_outfile,
		O_WRONLY | O_CREAT | O_TRUNC, S_IWUSR)) == NULL){
			kfree(k_args); kfree(k_keybuf);
			kfree(k_infile); kfree(k_outfile);
			kfree(buffer);
			// Close infile
			kfile_close(infile);
			return -EINVAL;	
		}
	}
	
	if(!(dst_len = (int *)kmalloc(sizeof(size_t), GFP_KERNEL))){
		kfree(k_args); kfree(k_keybuf);
		kfree(k_infile); kfree(k_outfile);
		kfree(buffer);
		// Close files
		kfile_close(infile);
		kfile_close(outfile);
		//kfile_unlink(outfile, k_outfile, strlen(k_outfile));
		printk(KERN_CRIT "No memory for dst_len\n");
		return -ENOMEM;
	}
	         
	/* --- Main I/O loop --- */
	bytes_read = -1;
	bytes_write = 0;
	offset_total = 0;
	while(bytes_read != 0){
		bytes_read = 0;
		bytes_read = kfile_read(infile, offset_total, buffer, page_size);
		if(bytes_read < 0){
			// Partial read encountered
			kfree(k_args); kfree(k_keybuf);
			kfree(k_infile); kfree(k_outfile);
			kfree(buffer); kfree(dst_len);
			// Close and Unlink file
			kfile_close(infile); 
			kfile_close(outfile);
			//kfile_unlink(outfile, k_outfile, strlen(k_outfile));
			return -EINVAL;
		} else if(bytes_read > 0){
			// Was read even with page_size?
			if(bytes_read == page_size){
				// page_size has been read
				// Is the LSB set to 1?
				if(k_flags == 1){
					// Encrypt buffer in place to save kernel resources
					*dst_len = bytes_read;
					src_len = bytes_read;
					i = 0;
					i = xencrypt_buffer(k_keybuf, k_keylen, 
						buffer, dst_len, buffer, src_len, 1);
					if(i != 0){
						kfree(k_args); kfree(k_keybuf);
						kfree(k_infile); kfree(k_outfile);
						kfree(buffer); kfree(dst_len);
						// Close and Unlink file
						kfile_close(infile); 
						kfile_close(outfile);
						//kfile_unlink(outfile, k_outfile, strlen(k_outfile));
						return -EINVAL;						
					} else {
						// Reset values
						src_len = 0;
					}
				} else {
					// Decrypt buffer
					*dst_len = bytes_read;
					src_len = bytes_read;
					i = 0;
					i = xdecrypt_buffer(k_keybuf, k_keylen, 
						buffer, dst_len, buffer, src_len, 1);
					if(i != 0){
						kfree(k_args); kfree(k_keybuf);
						kfree(k_infile); kfree(k_outfile);
						kfree(buffer); kfree(dst_len);
						// Close and Unlink file
						kfile_close(infile); 
						kfile_close(outfile);
						//kfile_unlink(outfile, k_outfile, strlen(k_outfile));
						return -EINVAL;						
					} else {
						// Reset values
						src_len = 0;
					}
				}
								
				// Write buffer
				//mutex_lock(&(outfile->f_dentry)->d_inode->i_mutex);
				bytes_write = kfile_write(outfile, offset_total, 
					buffer, *dst_len);
				//mutex_unlock(&(outfile->f_dentry)->d_inode->i_mutex);
				offset_total += bytes_write;
				
				if(bytes_write == -1){
					// Partial write encountered?
					kfree(k_args); kfree(k_keybuf);
					kfree(k_infile); kfree(k_outfile);
					kfree(buffer); kfree(dst_len);
					// Close and Unlink file
					kfile_close(infile);
					kfile_close(outfile);
					//kfile_unlink(outfile, k_outfile, strlen(k_outfile));
					return -EINVAL;
				}
			} else if(bytes_read < page_size){
				// bytes_read has been read
				// Is the LSB set to 1?
				if(k_flags == 1){
					// Encrypt buffer
					*dst_len = bytes_read;
					src_len = bytes_read;
					i = 0;
					i = xencrypt_buffer(k_keybuf, k_keylen, 
						buffer, dst_len, buffer, src_len, 0);
					if(i != 0){
						kfree(k_args); kfree(k_keybuf);
						kfree(k_infile); kfree(k_outfile);
						kfree(buffer); kfree(dst_len);
						// Close and Unlink file
						kfile_close(infile);
						kfile_close(outfile);
						//kfile_unlink(outfile, k_outfile, strlen(k_outfile));
						return -EINVAL;						
					} else {
						// Reset values
						src_len = 0;
					}
				} else {
					// Decrypt buffer
					*dst_len = bytes_read;
					src_len = bytes_read;
					i = 0;
					i = xdecrypt_buffer(k_keybuf, k_keylen, 
						buffer, dst_len, buffer, src_len, 0);
					if(i != 0){
						kfree(k_args); kfree(k_keybuf);
						kfree(k_infile); kfree(k_outfile);
						kfree(buffer); kfree(dst_len);
						// Close and Unlink file
						kfile_close(infile);
						kfile_close(outfile);
						//kfile_unlink(outfile, k_outfile, strlen(k_outfile));
						return -EINVAL;						
					} else {
						// Reset values
						// Last iteration, 
						//  so set bytes_read to 0 to exit
						bytes_read = 0; src_len = 0;
					}
				}
			 	
			 	// Write buffer
			 	//mutex_lock(&(outfile->f_dentry)->d_inode->i_mutex);
			 	bytes_write = kfile_write(outfile, offset_total, 
			 		buffer, *dst_len);
			 	//mutex_unlock(&(outfile->f_dentry)->d_inode->i_mutex);
			 	offset_total += bytes_write;

			 	if(bytes_write == -1){
			 		// Partial write encountered?
					kfree(k_args); kfree(k_keybuf);
					kfree(k_infile); kfree(k_outfile);
					kfree(buffer);
					// Close and Unlink files
					kfile_close(infile);
					kfile_close(outfile);
					//kfile_unlink(outfile, k_outfile, strlen(k_outfile));
					return -EINVAL;
			 	}
			 }
			 // Clear buffers
			 memset(buffer, 0, page_size);
		} // else bytes_read == 0, terminate while
	}
	
	// Close and Unlink files
	kfile_close(infile); 
	kfile_close(outfile);
	//kfile_unlink(outfile, k_outfile, strlen(k_outfile));
	// Free everything
	kfree(k_args); kfree(k_keybuf);
	kfree(k_infile); kfree(k_outfile);
	kfree(buffer);
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
