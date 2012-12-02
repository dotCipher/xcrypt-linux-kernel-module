#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "sys_xcrypt.h"
#include "xcipher.h"

void init_xcrypt_params(struct xcrypt_params *ptr){
	int i;
	/* Initialize and clear all params */
	ptr->outfile = malloc(sizeof((char)*OUTFILE_MAX));
	memset(ptr->outfile, 0, sizeof(strlen(ptr->outfile)));
	
	ptr->infile = malloc(sizeof((char)*INFILE_MAX));
	memset(ptr->infile, 0, sizeof(strlen(ptr->infile)));
	
	ptr->keybuf = malloc(sizeof((char)*PASS_MAX));
	memset(ptr->keybuf, 0, sizeof(strlen(ptr->keybuf)));
	
	ptr->keylen = 0;
	
	for(i = 0; i < 8; i++){
		ptr->flags &= ~(1 << i)
	}
	/* Return when done */
	return;
}

#ifdef EXTRA_CREDIT
	void init_valid_algorithms(char *algs[]){
		int i;
		/* Intialize and clear the whole array */
		for(i = 0; i < VALID_ALG_NUM; i++){
			if((algs[i] = (char*)malloc(sizeof((char)*16))) != NULL){
				memset(algs[i], 0, sizeof((char)*16));
			} else {
				perror("Error allocating memory for valid_algorithms: ");
				return;
			}	
		}
		/* Set all ciphers here */
		algs[0] = "aes";
		algs[1] = "anubis";
		algs[2] = "arc4";
		algs[3] = "blowfish";
		algs[4] = "cast5";
		algs[5] = "cast6";
		algs[6] = "des";
		algs[7] = "des3_ede";
		algs[8] = "khazad";
		algs[9] = "serpent";
		algs[10] = "twofish";
		/* Return when done */
		return;
	}
#endif

/* Handles checking if path is valid file	*/
/*   0 = Valid File							*/
/*   -1 = Invalid File						*/
int is_valid_file(char *path){
	struct stat *buf;
	int chk;
	
	// Malloc space for buffer
	buf = (struct stat*)malloc(sizeof(struct stat));
	if(buf == NULL){
		free(buf);
		return -1;
	}
	
	// Does the file exist?
	errno = 0;
	chk = stat(path, buf);
	if(errno != 0){
		if(chk == 0){
			free(buf);
			return -1;
		} else {
			free(buf);
			return 0;
		}
	} else {
		free(buf);
		return -1;
	}
	
	// Is the file NOT a directory?
	if(buf->st_mode & S_IFDIR){
		free(buf);
		return 0;
	} else {
		free(buf);
		return -1;
	}
	
	// Is the file a regular file?
	if(buf->st_mode & S_IFREG){
		free(buf);
		return 0;
	} else if(buf->st_mode & S_IFCHR){
		free(buf);
		return -1;
	} else if(buf->st_mode & S_IFBLK){
		free(buf);
		return -1;
	} else if(buf->st_mode & S_IFIFO){
		free(buf);
		return -1;
	} else if(buf->st_mode & S_IFSOCK){
		free(buf);
		return -1;
	} else if(buf->st_mode & S_IFDIR){
		free(buf);
		return -1;
	} else {
		free(buf);
		return -1;
	}
}

/* Checks if they are same file	*/
/*   0  = NOT the same file		*/
/*   -1 = IS the same file		*/
int is_same_file(char *file1, char *file2){
	// Inbuffer
	struct stat *buf1;
	// Outbuffer
	struct stat *buf2;
	buf1 = (struct stat*)malloc(sizeof(struct stat));
	buf2 = (struct stat*)malloc(sizeof(struct stat));
	stat(file1, buf1);
	stat(file2, buf2);
	// Are the basic paths the same?
	if(strcmp(file1, file2) == 0){
		free(buf1); free(buf2);
		return -1;
	} else {
		lstat(file1, buf1);
		lstat(file2, buf2);
		// Both NOT Symlinks?
		if(!(file1->st_mode & S_IFLNK) 
		&& !(file2->st_mode & S_IFLNK)){
			// Hardlines to same file?
			if((buf1->st_dev == buf2->st_dev) 
			&& (buf1->st_ino == buf2->st_ino)){
				free(buf1); free(buf2);
				return -1;
			} else {
				free(buf1); free(buf2);
				return 0;
			}
		// Both ARE Symlinks?
		} else if((buf1->st_mode & S_IFLNK)
		&& (buf2->st_mode & S_IFLNK){
			stat(file1, buf1);
			stat(file2, buf2);
			// Are they to the same file?
			if((buf1->st_dev == buf2->st_dev)
			&& (buf1->st_dev == buf2->st_dev)){
				free(buf1); free(buf2);
				return -1;
			} else {
				free(buf1); free(buf2);
				return 0;
			}
		// Inbuffer is a symlink?
		} else if((buf1->st_mode & S_IFLNK)
		&& !(buf2->st_mode & S_IFLNK)){
			stat(file1, buf1);
			stat(file2, buf2);
			if((buf1->st_dev == buf2->st_dev)
			&& (buf1->st_ino == buf2->st_ino)){
				free(buf1); free(buf2);
				return -1;
			} else {
				free(buf1); free(buf2);
				return 0;
			}
		// Outbuffer is a symlink
		} else {
			stat(file1, buf1);
			stat(file2, buf2);
			if((buf1->st_dev == buf2->st_dev)
			&& (buf1->st_ino == buf2->st_ino)){
				free(buf1); free(buf2);
				return -1;
			} else {
				free(buf1); free(buf2);
				return 0;
			}
		}
	}
}

/* Set Encryption Mode on Flag */
void set_encrypt_flag(struct xcrypt_params *ptr){
	
}

/* Set Decryption Mode on Flag */
void set_decrypt_flag(struct xcrypt_params *ptr){
	
}

/* - - - - - Main Method - - - - - */
int main(int argc, char *argv[]){
	/* Basic counter */
	int i;
	/* System Call Return Value */
	int xcrypt_rv;
	/* All Params Stored in Structure */
    struct xcrypt_params *params;
    /* Void Pointer to be passed to System Call */
	void *params_ptr;
	/* Booleans for flags */
	int opt, enc, dec, cip, pas, hlp;
	/* Error checking flags */
	int pasArgNum = -1;
	/* Valid ciphers */
	#ifdef EXTRA_CREDIT
		int alg_num = -1;
		char *valid_algs[VALID_ALG_NUM];
		init_valid_algorithms(valid_algs);
	#endif
	
	/* Parse out and check all parameters */
	opt = 0; enc = 0; dec = 0; cip = 0; pas = 0; hlp = 0;
	while((opt = getopt(argc, argv, "dec:hp:")) != -1){
		switch(opt){
			case 'd':
				dec = 1;
				break;
			case 'e':
				enc = 1;
				break;
			case 'h':
				hlp = 1;
				break;
			case 'p':
				if(strlen(optarg) > PASS_MAX){
					fprintf(stderr, "Error: Password cannot exceed %d characters\n", PASS_MAX);
					exit(EXIT_PASS_ERR);
				} else {
					strcpy(params->keybuf, optarg);
					pasArgNum = optind-1;
					pas = 1;
					break;
				}
			case 'c':
				#ifdef EXTRA_CREDIT
					for(i = 0; i < VALID_ALG_NUM; i++){
						if(strcmp(optarg, valid_algs[i]) == 1){
							alg_num = i;
						}
					}
					if(alg_num == -1){
						fprintf(stderr, "Error: Invalid algorithm argument specified for -c\n");
						exit(EXIT_CIPHER_ERR);
					}
				#else
					goto default;
				#endif
			default:
				fprintf(stderr, "Error: Invalid execution\n");
				fprintf(stderr,"Usage: %s [OPTIONS] [-p PASSWORD] <infile> <outfile>\n", argv[0]);
				exit(EXIT_INPUT_ERR);
		}
	}
	
	/* Boolean checking of input */
	if(hlp == 1){
		printf("XCipher Tool by Cody Moore \n");
		printf("Usage: %s [OPTIONS] [-p PASSWORD] <infile> <outfile> \n", argv[0]);
		printf("- - - OPTIONS - - -\n");
		printf("   -p [PASS] :  Use [PASS] as password (skip prompt) \n");
		printf("   -d        :  Decrypt <infile> to <outfile> \n");
		printf("   -e        :  Encrypt <infile> to <outfile> \n");
		printf("   -h        :  Show help screen (you are looking at it) \n");
		#ifdef EXTRA_CREDIT
			printf("   -c [ALG]  :  Use [ALG] algorithm to encrypt or decrypt file\n");
			printf("- - - CIPHERS - - -\n");
			printf("   aes      :  Advanced Encryption Standard (AES)\n");
			printf("   anubis   :  Anubis Cipher Algorithm\n");
			printf("   arc4     :  ARC4 (RC4) Cipher Algorithm\n");
			printf("   blowfish :  Blowfish Cipher Algorithm\n");
			printf("   cast5    :  CAST-128 (CAST5) Cipher Algorithm\n");
			printf("   cast6    :  CAST-256 (CAST6) Cipher Algorithm\n");
			printf("   des      :  Data Encryption Standard (DES)\n");
			printf("   des3_ede :  Triple DES (3DES)\n");
			printf("   khazad   :  KHAZAD Cipher Algorithm\n");
			printf("   serpent  :  Serpent Cipher Algorithm\n");
			printf("   twofish  :  Twofish Cipher Algorithm\n");
		#endif
		exit(EXIT_HELP);
	} else if(argc >= 4){
		/* More error checking */
		if((strcmp(argv[passArgNum], argv[argc-2]) == 0) && passArgNum != 0){
			fprintf(stderr, "Error: No <outfile> specified\n");
			exit(EXIT_INPUT_ERR);
		}
		/* Take <infile> and <outfile> */
		strcpy(params->infile, argv[argc-2]);
		strcpy(params->outfile, argv[argc-1]);
		
		/* Error check <infile> */
		if(!(is_valid_file(params->infile))){
			free(params->infile);
			free(params->outfile);
			free(params->keybuf);
			exit(EXIT_INFILE_ERR);
		}
		
		/* Error check <outfile> */
		if(!(is_valid_file(params->outfile))){
			free(params->infile);
			free(params->outfile);
			free(params->keybuf);
			exit(EXIT_OUTFILE_ERR);
		}
		
		/* Error check same file */
		if(is_same_file(params->infile, params->outfile)){
			free(params->infile);
			free(params->outfile);
			free(params->keybuf);
			exit(EXIT_IN_OUT_ERR);
		}
		
		/* Encrypt or Decrypt Conditions */
		if(dec == 0 && enc == 1){
			// Do bitshift of flags for params
			// get keylen from strlen(params->keybuf)
			// Pass Params to system call
			// Return and output finished
			// Exit from program
		} else if(dec == 1 && enc == 0){
		
		} else if(dec == 1 && enc == 1){
		
		} else { //dec == 0 && enc == 0
			
		}
		
		////////////////////////////////
		/* Main execution starts here */
		////////////////////////////////
		
		
	} else {
		/* Invalid input error */
		fprintf(stderr, "Error: Invalid execution\n");
		fprintf(stderr, "Usage: %s [OPTIONS] [-p PASSWORD] <infile> <outfile>\n", argv[0]);
		exit(EXIT_INPUT_ERR);
	}
	
	/////////////////////////
	/*  EXAMPLE CODE HERE  */
	/////////////////////////
	params_ptr = (void *) params;
	
	printf("Test return: %s\n", params->infile);
	
	
	xcrypt_rv = 0;
  	//xcrypt_rv = syscall(__NR_xcrypt, params_ptr);
	//printf("system call returned with %d\n", xcrypt_rv);
	
	//free(params->infile);
	exit(xcrypt_rv);
}
