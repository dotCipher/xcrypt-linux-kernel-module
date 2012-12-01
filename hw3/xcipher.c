#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "sys_xcrypt.h"
#include "xcipher.h"

void init_xcrypt_params(struct xcrypt_params *ptr){
	int i;
	
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
	
	/* Start main execution */
	if(hlp == 1){
		
	}
	
	params_ptr = (void *) params;
	
	printf("Test return: %s\n", params->infile);
	
	
	xcrypt_rv = 0;
  	//xcrypt_rv = syscall(__NR_xcrypt, params_ptr);
	//printf("system call returned with %d\n", xcrypt_rv);
	
	//free(params->infile);
	exit(xcrypt_rv);
}
