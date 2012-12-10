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
	ret = vfs_unlink(file->f_dentry->d_parent->d_inode, file->f_dentry);
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

int kfile_sync(struct file* file){
	vfs_fsync(file, 0);
	return 0;
}

int is_same_kfile(struct file* file1, struct file* file2){
	if(file1->f_dentry->d_inode->i_ino == file2->f_dentry->d_inode->i_ino 
	&& file1->f_dentry->d_sb == file2->f_dentry->d_sb){
		return 1;
	} else {
		return 0;
	}
}

int init_scatterlist(const void *buffer, int len, struct scatterlist *sg,
int sg_len){
	int i = 0;
	struct page *pg;
	int off;
	int remainder;
	
	sg_init_table(sg, sg_len);
	
	while(len > 0 && i < sg_len){
		pg = virt_to_page(buffer);
		off = offset_in_page(buffer);
		if(sg){
			sg_set_page(&sg[i], pg, 0, off);
		}
		remainder = PAGE_CACHE_SIZE - off;
		if(len >= remainder){
			if(sg){
				sg[i].length = remainder;
			}
			buffer += remainder;
			len += remainder;
		} else {
			if(sg){
				sg[i].length = len;
			}
			buffer += len;
			len = 0;
		}
		i++;
	}
	if(len > 0){
		return -ENOMEM;
	}
	return i;
}

static struct crypto_blkcipher *xcrypt_alloc_tfm(void){
	return crypto_alloc_blkcipher("cbc(aes)", 0, CRYPTO_ALG_ASYNC);
}

int xcrypt_cipher(void *key, int keylen, char *to_buffer, 
char *from_buffer, int buffer_len, int enc_flag){
	// Declare all needed variables
	struct scatterlist *src;
	struct scatterlist *dst;
	struct crypto_blkcipher *tfm = xcrypt_alloc_tfm();
	char *new_key;
	int ret, i;
	void *iv;
	int ivsize;
	// change this to add ivs
	struct blkcipher_desc desc = {
		.tfm = tfm, .flags = CRYPTO_TFM_REQ_MAY_SLEEP };
	ret = 1; i = 0;
	
	if(IS_ERR(tfm)){
		ret = PTR_ERR(tfm);
		printk(KERN_CRIT "Cant load transform\n");
		crypto_free_blkcipher(tfm);
		return ret;
	}
	printk(KERN_CRIT "Setting crypto cipher key\n");
	
	// Force pad key with nulls
	if(!(new_key = kmalloc(16, GFP_KERNEL))){
		crypto_free_blkcipher(tfm);
		return -ENOMEM;
	}
	if(keylen < 16){
			new_key = key;
		for(i = keylen; i < 16; i++){
			new_key[i] = '\0';
		}
	} else {
		new_key = key;
	}
	
	printk(KERN_CRIT "newkey = %s\n", new_key);
	printk(KERN_CRIT "key = %s\n", key);
	crypto_blkcipher_setkey((void *)tfm, new_key, 16);
	/*
	if(ret){
		printk(KERN_CRIT "setkey() failed\n");
		crypto_free_cipher(tfm);
		return ret;
	}
	*/
	sg_init_table(src, 1);
	sg_set_buf(&src[0], from_buffer, buffer_len);
	sg_init_table(dst, 1);
	sg_set_buf(&dst[0], to_buffer, buffer_len);
	
	// Set Initialization Vector
	printk(KERN_CRIT "Setting iv.\n");
	iv = crypto_blkcipher_crt(tfm)->iv;
	ivsize = crypto_blkcipher_ivsize(tfm);
	printk(KERN_CRIT "ivsize = %d\n", ivsize);
	
	// Alloc mem for iv
	if(!(iv = kmalloc(ivsize, GFP_KERNEL))){
		crypto_free_blkcipher(tfm);
		return -ENOMEM;
	}
	
	memcpy(iv, (u8 *)"x8QR55HKpW52464q", ivsize);
	printk(KERN_CRIT "iv = %s\n", (unsigned char *)iv);

	//printk(KERN_CRIT "tfm->crt_flags = %d\n", tfm->crt_flags);
	
	if(enc_flag == 1){
		printk(KERN_CRIT "Encrypting in xcrypt_cipher()\n");
		ret = crypto_blkcipher_encrypt(&desc, dst, src, buffer_len);
		/*
		for(i = 0; i < buffer_len; i++){
			tmp_src = from_buffer[i];
			printk(KERN_CRIT "index in buffer = %d\n", i);
			printk(KERN_CRIT "src_char = %c\n", tmp_src);
			crypto_cipher_encrypt_one(tfm, tmp_dst, tmp_src);
			printk(KERN_CRIT "dst_char = %c\n", tmp_dst);
			to_buffer[i] = tmp_dst;
		}
		*/
	} else {
		printk(KERN_CRIT "Decrypting in xcrypt_cipher()\n");
		ret = crypto_blkcipher_decrypt(&desc, dst, src, buffer_len);
		/*
		for(i = 0; i < buffer_len; i++){
			tmp_src = from_buffer[i];
			crypto_cipher_decrypt_one(tfm, tmp_dst, tmp_src);
			to_buffer[i] = tmp_dst;
		}
		*/
	}
	
	crypto_free_blkcipher(tfm);
	
	if(ret < 0){
		printk(KERN_CRIT "Encryption failed\n");
		kfree(new_key);
		return ret;
	}
	printk(KERN_CRIT "Returning from xcrypt_cipher()\n");
	kfree(new_key);
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
	int offset_total;
	int params_len = sizeof(struct xcrypt_params);
	int i;
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
	if(!(k_keybuf = kmalloc(k_keylen, GFP_KERNEL))){
		kfree(k_args);
		return -ENOMEM;
	}
	if(!access_ok(VERIFY_READ, ((struct xcrypt_params *)k_args)->keybuf,
	k_keylen)){
		kfree(k_args); kfree(k_keybuf);
		return -EFAULT;
	}
	if(copy_from_user(k_keybuf, ((struct xcrypt_params *)k_args)->keybuf,
	k_keylen)){
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
	printk(KERN_CRIT "k_infile = %s\n", k_infile);
	printk(KERN_CRIT "k_outfile = %s\n", k_outfile);
	printk(KERN_CRIT "k_keybuf = %s\n", k_keybuf);
	printk(KERN_CRIT "k_keylen = %d\n", k_keylen);
	printk(KERN_CRIT "k_flags = %d\n", k_flags);
	
	// Clear buffer
	if(!(buffer = (unsigned char *)kmalloc(page_size, GFP_KERNEL))){
		kfree(k_args); kfree(k_keybuf);
		kfree(k_infile); kfree(k_outfile);
		printk(KERN_CRIT "No memory for buffer 1");
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
		kfile_close(outfile); kfile_unlink(outfile);
		return -EINVAL;
	} else {
		// Not the same file, re open outfile 
		kfile_close(outfile); //kfile_unlink(outfile);
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

	printk(KERN_CRIT "--- Entering Main I/O Loop ---\n");
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
			kfree(buffer);
			// Close and Unlink file
			kfile_close(infile); 
			kfile_close(outfile); kfile_unlink(outfile);
			return -EINVAL;
		} else if(bytes_read > 0){
			// Was read even with page_size?
			if(bytes_read == page_size){
				// page_size has been read
				// Is the LSB set to 1?
				if(k_flags == 1){
					// Encrypt buffer
					printk(KERN_CRIT "Calling xcrypt_cipher(encrypt)\n");
					i = xcrypt_cipher(k_keybuf, k_keylen, 
						buffer, buffer, page_size, 1);
					if(i != 0){
						kfree(k_args); kfree(k_keybuf);
						kfree(k_infile); kfree(k_outfile);
						kfree(buffer);
						// Close and Unlink file
						kfile_close(infile); 
						kfile_close(outfile); kfile_unlink(outfile);
						return -EINVAL;						
					}
				} else {
					// Decrypt buffer
					printk(KERN_CRIT "Calling xcrypt_cipher(decrypt)\n");
					i = xcrypt_cipher(k_keybuf, k_keylen, 
						buffer, buffer, page_size, 0);
					if(i != 0){
						kfree(k_args); kfree(k_keybuf);
						kfree(k_infile); kfree(k_outfile);
						kfree(buffer);
						// Close and Unlink file
						kfile_close(infile); 
						kfile_close(outfile); kfile_unlink(outfile);
						return -EINVAL;						
					}
				}
								
				// Lock and Write buffer
				mutex_lock(&(outfile->f_dentry)->d_inode->i_mutex);
				bytes_write = kfile_write(outfile, offset_total, 
					buffer, page_size);
				mutex_unlock(&(outfile->f_dentry)->d_inode->i_mutex);
				offset_total += bytes_write;
				
				if(bytes_write == -1){
					// Partial write encountered?
					kfree(k_args); kfree(k_keybuf);
					kfree(k_infile); kfree(k_outfile);
					kfree(buffer);
					// Close and Unlink file
					kfile_close(infile);
					kfile_close(outfile); kfile_unlink(outfile);
					return -EINVAL;
				}
			 } else if(bytes_read < page_size){
			 	// bytes_read has been read
				// Is the LSB set to 1?
				if(k_flags == 1){
					// Encrypt buffer
					printk(KERN_CRIT "Calling xcrypt_cipher(encrypt)\n");
					i = xcrypt_cipher(k_keybuf, k_keylen, 
						buffer, buffer, bytes_read, 1);
					if(i != 0){
						kfree(k_args); kfree(k_keybuf);
						kfree(k_infile); kfree(k_outfile);
						kfree(buffer);
						// Close and Unlink file
						kfile_close(infile);
						kfile_close(outfile); kfile_unlink(outfile);
						return -EINVAL;						
					}
				} else {
					// Decrypt buffer
					printk(KERN_CRIT "Calling xcrypt_cipher(decrypt)\n");
					i = xcrypt_cipher(k_keybuf, k_keylen, 
						buffer, buffer, bytes_read, 0);
					if(i != 0){
						kfree(k_args); kfree(k_keybuf);
						kfree(k_infile); kfree(k_outfile);
						kfree(buffer);
						// Close and Unlink file
						kfile_close(infile);
						kfile_close(outfile);kfile_unlink(outfile);
						return -EINVAL;						
					}
				}
			 	
			 	// Write buffer
			 	mutex_lock(&(outfile->f_dentry)->d_inode->i_mutex);
			 	bytes_write = kfile_write(outfile, offset_total, 
			 		buffer, bytes_read);
			 	mutex_unlock(&(outfile->f_dentry)->d_inode->i_mutex);
			 	offset_total += bytes_write;
			 	
			 	if(bytes_write == -1){
			 		// Partial write encountered?
					kfree(k_args); kfree(k_keybuf);
					kfree(k_infile); kfree(k_outfile);
					kfree(buffer);
					// Close and Unlink files
					kfile_close(infile);
					kfile_close(outfile); kfile_unlink(outfile);
					return -EINVAL;
			 	}
			 }
			 // Clear buffer
			 memset(buffer, 0, page_size);
		} // else bytes_read == 0, terminate while
	}
	
	// Close and Unlink files
	kfile_close(infile); 
	kfile_close(outfile); kfile_unlink(outfile);
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
