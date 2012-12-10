/* Private system call number */
#define __NR_xcrypt 349

/* Extra Credit Boolean */
//#define EXTRA_CREDIT 1

/* Max values */
#define PASS_MAX 16
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

