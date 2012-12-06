/* Private system call number */
#define __NR_xcrypt 349

/* Extra Credit Boolean */
#define EXTRA_CREDIT 1

/* Max values */
#define PASS_MAX 64
#define INFILE_MAX 256
#define OUTFILE_MAX 256

/* Numerical helpers */
#define VALID_ALG_NUM 11

/* Error codes */
#define EXIT_CIPHER_ERR -6
#define EXIT_IN_OUT_ERR -5
#define EXIT_OUTFILE_ERR -4
#define EXIT_INFILE_ERR -3
#define EXIT_PASS_ERR -2
#define EXIT_INPUT_ERR -1
#define EXIT_SUCCESS 0
#define EXIT_HELP 1

/* Struct to use for params */
struct xcrypt_params{
	char *infile;
	char *outfile;
	char *keybuf;
	int keylen;
	unsigned char flags;
};

// -1 = Failure  0 = Success
int init_xcrypt_params(struct xcrypt_params *ptr){
    int i;
    /* Initialize and clear all params */
    ptr = (struct xcrypt_params *)malloc(sizeof(struct xcrypt_params));        
    if((ptr->outfile = (char *)calloc(OUTFILE_MAX, sizeof(char))) == NULL){
    	perror("Error allocating memory for outfile parameter: ");
        return -1;
	}
	if((ptr->infile = (char *)calloc(INFILE_MAX, sizeof(char))) == NULL){
		perror("Error allocating memory for infile parameter: ");
		return -1;
	}
	if((ptr->keybuf = (char *)calloc(PASS_MAX, sizeof(char))) == NULL){
		perror("Error allocating memory for keybuf parameter: ");
        return -1;
	}
	ptr->keylen = 0;
	for(i = 0; i < 8; i++){
    	ptr->flags &= ~(1 << i);
    }
    /* Return when done */
    return 0;
}  

void free_xcrypt_params(struct xcrypt_params *ptr){
	free(ptr->outfile);
	free(ptr->infile);
	free(ptr->keybuf);
	free(ptr);
	return;
}

#ifdef EXTRA_CREDIT
	// -1 = Failure   0 = Success
	int init_valid_algorithms(char *algs[]){
		int i;
		/* Initialize and clear the whole array */
		for(i = 0;  i < VALID_ALG_NUM; i++){
			if((algs[i] = (char *)calloc(16, sizeof(char))) == NULL){
				perror("Error allocating memory for valid_algorithms:  ");
				return -1;
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
		return 0;
	}
	void free_valid_algorithms(char *algs[]){
		int i;
		for(i = 0; i < VALID_ALG_NUM; i++){
			free(algs[i]);
		}
	}
#endif
