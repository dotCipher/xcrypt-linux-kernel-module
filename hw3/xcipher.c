#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "common.h"

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
		if(!(buf1->st_mode & S_IFLNK) 
		&& !(buf2->st_mode & S_IFLNK)){
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
		&& (buf2->st_mode & S_IFLNK)){
			stat(file1, buf1);
			stat(file2, buf2);
			// Are they to the same file?
			if((buf1->st_dev == buf2->st_dev)
			&& (buf1->st_ino == buf2->st_ino)){
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
	// Is encrypt set already?
	// flag: [---- ---?]
	if(ptr->flags & (1 << 0)){
		// If it is, do nothing
		return;
	} else { // set flag for encryption
		// flag: [---- ---1]
		ptr->flags |= (1 << 0);
		return;
	}
}

/* Set Decryption Mode on Flag */
void set_decrypt_flag(struct xcrypt_params *ptr){
	// Is decrypt set already?
	// flag: [---- ---?]
	if(ptr->flags & (1 << 0)){
		// If it is set, switch to decrypt mode
		// flag: [---- ---0]
		ptr->flags &= ~(1 << 0);
		return;
	} else {
		// Do nothing
		return;
	}
}

void set_algs(char *algs[]){
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

/* Handles checking if file exists
* as well as proper permissions on file
* SUCCESS CODE(S):
* 0 = Success (File DOES NOT exist)
* ERROR CODE(S):
* 1 = File does exist
* 2 = File does exist & no permissions
*/
int fileExists(char *fname){
	struct stat buf;
	errno = 0;
	int chk = stat(fname, &buf);
	if(errno!=0){
		return (chk == 0);
	} else {
		return 2;
	}
}

/* - - - - - Main Method - - - - - */
int main(int argc, char *argv[]){
	/* Basic counter */
	int i;
	/* System Call Return Value */
	int xcrypt_rv;
	/* All Params Stored in Structure */
    struct xcrypt_params *params;
    int outfile_fd;
    /* Void Pointer to be passed to System Call */
	void *params_ptr;
	/* Booleans for flags */
	int opt, enc, dec, cip, pas, hlp;
	/* Error checking flags */
	int passArgNum = -1;
	/* Declare valid ciphers */
	#ifdef EXTRA_CREDIT
		int alg_num = -1;
		char *algs[VALID_ALG_NUM];
	#endif
	/* Init xcrypt params */
	if((params = malloc(sizeof *params)) == NULL){
		perror("Error allocating memory for struct: ");
		exit(EXIT_IN_OUT_ERR);
	}
	if((params->outfile = (char *)calloc(OUTFILE_MAX, sizeof(char))) == NULL){
		perror("Error allocating memory for outfile: ");
		free(params);
		exit(EXIT_OUTFILE_ERR);
	}
	if((params->infile = (char *)calloc(INFILE_MAX, sizeof(char))) == NULL){
		perror("Error allocating memory for infile: ");
		free(params->outfile);
		free(params);
		exit(EXIT_INFILE_ERR);
	}
	if((params->keybuf = (char *)calloc(PASS_MAX, sizeof(char))) == NULL){
		perror("Error allocating memory for keybuf parameter: ");
		free(params->infile); free(params->outfile);
		free(params);
		exit(EXIT_PASS_ERR);
	}
	params->keylen = 0;
	for(i = 0; i < 8; i++){
		params->flags &= ~(1 << i);
	}
	
	/* Init valid ciphers */
	#ifdef EXTRA_CREDIT
		for(i = 0; i < VALID_ALG_NUM; i++){
			if((algs[i] = (char *)calloc(32, sizeof(char))) == NULL){
				perror("Error allocating memory for valid algs: ");
				free(params->infile); free(params->outfile);
				free(params->keybuf); free(params);
				exit(EXIT_CIPHER_ERR);
			}
		}
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
					#ifdef EXTRA_CREDIT
						for(i = 0; i < VALID_ALG_NUM; i++){
							free(algs[i]);
						}
					#endif
					free(params->infile); free(params->outfile);
					free(params->keybuf); free(params);
					exit(EXIT_PASS_ERR);
				} else {
					strcpy(params->keybuf, optarg);
					params->keylen = strlen(params->keybuf)+1;
					printf("Keylength is: %d\n", params->keylen);
					passArgNum = optind-1;
					pas = 1;
					
					printf("Password accepted...\n");
					
					break;
				}
			case 'c':
				#ifdef EXTRA_CREDIT
					for(i = 0; i < VALID_ALG_NUM; i++){
						if(strcmp(optarg, algs[i]) == 1){
							alg_num = i;
						}
					}
					if(alg_num == -1){
						fprintf(stderr, "Error: Invalid algorithm argument specified for -c\n");
						for(i = 0; i < VALID_ALG_NUM; i++){
							free(algs[i]);
						}
						free(params->infile); free(params->outfile);
						free(params->keybuf); free(params);
						exit(EXIT_CIPHER_ERR);
					}
				#else
					goto default;
				#endif
			default:
				fprintf(stderr, "Error: Invalid execution\n");
				fprintf(stderr,"Usage: %s [OPTIONS] [-p PASSWORD] <infile> <outfile>\n", argv[0]);
				#ifdef EXTRA_CREDIT
					for(i = 0; i < VALID_ALG_NUM; i++){
						free(algs[i]);
					}
				#endif
				free(params->infile); free(params->outfile);
				free(params->keybuf); free(params);
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
			for(i = 0; i < VALID_ALG_NUM; i++){
				free(algs[i]);
			}
		#endif
		free(params->infile); free(params->outfile);
		free(params->keybuf); free(params);
		exit(EXIT_HELP);
	} else if(argc > 4){
		
		printf("ARGC = %d\n", argc);
		
		/* More error checking */
		if((strcmp(argv[passArgNum], argv[argc-2]) == 0) && passArgNum != 0){
			fprintf(stderr, "Error: No <outfile> specified\n");
			#ifdef EXTRA_CREDIT
				for(i = 0; i < VALID_ALG_NUM; i++){
					free(algs[i]);
				}
			#endif
			free(params->infile); free(params->outfile);
			free(params->keybuf); free(params);
			exit(EXIT_INPUT_ERR);
		}
		/* Take <infile> and <outfile> */
		strcpy(params->infile, argv[argc-2]);
		strcpy(params->outfile, argv[argc-1]);
		
		/* Error check <infile> */
		errno = 0;
		if(!(is_valid_file(params->infile))){
			#ifdef EXTRA_CREDIT
				for(i = 0; i < VALID_ALG_NUM; i++){
					free(algs[i]);
				}
			#endif
			free(params->infile); free(params->outfile);
			free(params->keybuf); free(params);
			fprintf(stderr, "Error: Infile invalid\n");
			exit(EXIT_INFILE_ERR);
		}
		
		/* Error check <outfile> */
		if((fileExists(params->outfile))!=1){
			// outfile does not exist
			// Create it
			errno = 0;
			outfile_fd = open(params->outfile, O_RDWR | O_CREAT | O_TRUNC | O_APPEND, S_IWRITE);
		}
		if(!(is_valid_file(params->outfile)) || outfile_fd == -1){
			#ifdef EXTRA_CREDIT
				for(i = 0; i < VALID_ALG_NUM; i++){
					free(algs[i]);
				}
			#endif
			free(params->infile); free(params->outfile);
			free(params->keybuf); free(params);
			fprintf(stderr, "Error: Outfile invalid\n");
			exit(EXIT_OUTFILE_ERR);
		} else {
			close(outfile_fd);
		}
		
		/* Error check same file */
		if(is_same_file(params->infile, params->outfile)){
			#ifdef EXTRA_CREDIT
				for(i = 0; i < VALID_ALG_NUM; i++){
					free(algs[i]);
				}
			#endif
			free(params->infile); free(params->outfile);
			free(params->keybuf); free(params);
			fprintf(stderr, "Error: infile and outfile are the same\n");
			exit(EXIT_IN_OUT_ERR);
		}
		
		/* Encrypt or Decrypt Conditions */
		if(dec == 0 && enc == 1){
			// Do bitshift of flags for params
			set_encrypt_flag(params);
			// get keylen from strlen(params->keybuf)
			params->keylen = strlen(params->keybuf);
			// Pass Params to system call
			params_ptr = (void *)params;
			xcrypt_rv = 0;
			printf("Encrypting file...\n");
			xcrypt_rv = syscall(__NR_xcrypt, params_ptr);
			
			// Return and output finished
			if(xcrypt_rv == 0){
				printf("syscall returned with %d\n", xcrypt_rv);
			} else {
				printf("syscall returned with %d\n (errno = %d)\n", xcrypt_rv, errno);
			}
			
			// Free all memory used
			#ifdef EXTRA_CREDIT
				for(i = 0; i < VALID_ALG_NUM; i++){
					free(algs[i]);
				}
			#endif
			free(params->infile); free(params->outfile);
			free(params->keybuf); free(params);
			// Exit from program
			printf("Done!\n");
			exit(EXIT_SUCCESS);
		} else if(dec == 1 && enc == 0){
			// Do bitshift of flags for params
			set_decrypt_flag(params);
			// get keylen from strlen(params->keybuf)
			params->keylen = strlen(params->keybuf);
			// Pass Params to system call
			params_ptr = (void *)params;
			xcrypt_rv = 0;
			printf("Decrypting the file...\n");
			xcrypt_rv = syscall(__NR_xcrypt, params_ptr);
			
			// Return and output finished
			if(xcrypt_rv == 0){
				printf("syscall returned with %d\n", xcrypt_rv);
			} else {
				printf("syscall returned with %d\n (errno = %d)\n", xcrypt_rv, errno);
			}
			
			// Free all memory used
			#ifdef EXTRA_CREDIT
				for(i = 0; i < VALID_ALG_NUM; i++){
					free(algs[i]);
				}
			#endif
			free(params->infile); free(params->outfile);
			free(params->keybuf); free(params);
			// Exit from program
			printf("Done!\n");
			exit(EXIT_SUCCESS);
		} else if(dec == 1 && enc == 1){
			// Error cannot both decrypt and encrypt
			fprintf(stderr, "Error: Cannot both encrypt and decrypt\n");
			fprintf(stderr, "Usage: %s [OPTIONS] [-p PASSWORD] <infile> <outfile>\n", argv[0]);
			// Free all memory used
			#ifdef EXTRA_CREDIT
				for(i = 0; i < VALID_ALG_NUM; i++){
					free(algs[i]);
				}
			#endif
			free(params->infile); free(params->outfile);
			free(params->keybuf); free(params);
			exit(EXIT_INPUT_ERR);
		} else { //dec == 0 && enc == 0
			// Error must either decrypt or encrypt
			fprintf(stderr, "Error: Must either encrypt or decrypt\n");
			fprintf(stderr, "Usage: %s [OPTIONS] [-p PASSWORD] <infile> <outfile>\n", argv[0]);
			// Free all memory used
			#ifdef EXTRA_CREDIT
				for(i = 0; i < VALID_ALG_NUM; i++){
					free(algs[i]);
				}
			#endif
			free(params->infile); free(params->outfile);
			free(params->keybuf); free(params);
			exit(EXIT_INPUT_ERR);
		}	
		
	} else {
		/* Invalid input error */
		fprintf(stderr, "Error: Invalid execution\n");
		fprintf(stderr, "Usage: %s [OPTIONS] [-p PASSWORD] <infile> <outfile>\n", argv[0]);
		#ifdef EXTRA_CREDIT
			for(i = 0; i < VALID_ALG_NUM; i++){
				free(algs[i]);
			}
		#endif
		free(params->infile); free(params->outfile);
		free(params->keybuf); free(params);
		exit(EXIT_INPUT_ERR);
	}
	
	/////////////////////////
	/*  EXAMPLE CODE HERE  */
	/////////////////////////
	//params_ptr = (void *) params;
	
	//printf("Test return: %s\n", params->infile);
	
	//xcrypt_rv = 0;
  	//xcrypt_rv = syscall(__NR_xcrypt, params_ptr);
	//printf("system call returned with %d\n", xcrypt_rv);
	
	//free(params->infile);
	//exit(xcrypt_rv);
}
