#include "common.h"
#include "prng.h"
#include "entropy_pool.h"
#include "yarrow.h"
#include "hash_desc.h"
#include "macros.h"
#include "prng.h"
#include "gost.h"
#include "idea.h"
#include "cipher_desc.h"
#include "feed_entropy.h"

typedef enum {
	PrngCipher, PrngHash,
	EntropyHash, 
	TimeParam, GateParam,
	Nsources,
	K
} ServerOpCodes;

static const char	*program_name;

static struct {
	char *name;
	ServerOpCodes opcode;

} attr_table [] = { 

	{"prng_cipher", PrngCipher},
	{"prng_hash", PrngHash},
	{"entropy_hash", EntropyHash},
	{"time_param", TimeParam},
	{"gate", GateParam},
	{"nsources", Nsources},
	{"k", K}
};

typedef struct {
	char prng_cipher[16];
	char prng_hash[16];
	char entropy_hash[16];
	int time_param;
	int gate_param;
	int nsources;
	int k;
}	Options;

Options options;

static void set_program_name(int argc, char *argv[])
{
	char *s;

	program_name = ((s = strrchr(argv[0], '/')) != NULL) ? ++s : argv[0];
}

static void print_used()
{
	printf("Usage: %s [OPTIONS] [FILE]\n"
	       "Options: \n"
	       "  -f <config-file>		path config file\n"
	       "\n"
	       "If no FILE provided, then value will default\n",
	       program_name);
}

#define WHITESPACE " \n\t\r"
#define QUOTE "\""

char *
strdelim(char **s)
{
	char *old;
	int wspace = 0;

	if (*s == NULL)
		return NULL;

	old = *s;
	*s = strpbrk(*s, WHITESPACE QUOTE "=");
	if (*s == NULL)
		return (old);

	if (*s[0] == '\"') {
		memmove(*s, *s + 1, strlen(*s)); /* move nul too */
		/* Find matching quote */
		if ((*s = strpbrk(*s, QUOTE)) == NULL) {
			return (NULL);		/* no matching quote */
		} else {
			*s[0] = '\0';
			*s += strspn(*s + 1, WHITESPACE) + 1;
			return (old);
		}
	}

	/* Allow only one '=' to be skipped */
	if (*s[0] == '=')
		wspace = 1;
	*s[0] = '\0';

	/* Skip any extra whitespace after first token */
	*s += strspn(*s + 1, WHITESPACE) + 1;
	if (*s[0] == '=' && !wspace)
		*s += strspn(*s + 1, WHITESPACE) + 1;

	return (old);
}



int process_server_config(const char *filename)
{
	int i, value, linenum;
	FILE *fd;
	char *line, *ptr;
	char *arg;
	ServerOpCodes opcode;

	linenum = 1;
	ptr = line = calloc(128, 1);
	
	fd = fopen(filename, "rw");
	if (fd == 0)
		return FALSE;

	while (fgets(line, 127, fd) != NULL) {
		linenum++;

		if ((arg = strdelim(&line)) == NULL) {
		//	printf("arg %s\n", arg);
			continue;
		}
		
		/* Ignore leading whitespace */
		if (*arg == '\0')
			arg = strdelim(&line);

		if (!arg || !*arg || *arg == '#')
		continue;

		for (i = 0; attr_table[i].name; i++) {
			if (strcasecmp(arg, attr_table[i].name) == 0) {
				opcode = attr_table[i].opcode;
				break;
			}
		}
		
//		printf("arg %s name %s", arg, attr_table[i].name);
		switch(opcode) {
		case PrngCipher:
			arg = strdelim(&line);
			strncpy(options.prng_cipher, arg, 16);
			break;
		case PrngHash:
			arg = strdelim(&line);
			strncpy(options.prng_hash, arg, 16);
			break;
		case EntropyHash:
			arg = strdelim(&line);
			strncpy(options.entropy_hash, arg, 16);
			break;
		case GateParam:
			arg = strdelim(&line);
			if (!arg || *arg == '\0')
				printf("%s line %d: missing integer value.",
				     filename, linenum);
			
			value = atoi(arg);
			options.gate_param = value;
			break;
		case TimeParam:
			arg = strdelim(&line);
			if (!arg || *arg == '\0')
				printf("%s line %d: missing integer value.",
				    filename, linenum);
			
			value = atoi(arg);
			if (value < MIN_TIME_PARAM)
				value = MIN_TIME_PARAM;
			options.time_param = value;
			break;
		case Nsources:
			arg = strdelim(&line);
			if (!arg || *arg == '\0')
				printf("%s line %d: missing integer value.",
				      filename, linenum);
			
			value = atoi(arg);
			options.nsources = value;
			break;
		case K:
			arg = strdelim(&line);
			if (!arg || *arg == '\0')
				printf("%s line %d: missing integer value.",
				      filename, linenum);
			
			value = atoi(arg);
			options.k = value;
			break;
		default:
			printf("%s: line %d: mising handler for opcode %s\n", filename, linenum, arg);
		}
	
		if ((arg = strdelim(&line)) != NULL && *arg != '\0')
			printf("%s line %d: garbage at end of line; \"%.200s\".",
			       filename, linenum, arg);
		line = ptr;
	}

	free(ptr);

	if(fclose(fd) != 0) {
//		printf("error of fclose\n");
		exit(1);
	}
	return TRUE;
}

struct entropy_pool fast_pool, slow_pool;
int add_to_fast[MAXSOURCES];

int main(int argc, char **argv)
{
	int opt, res, i, fd;
//	size_t size = 512;
//	int buf_random[512];
//	char buf[128];
//	double treshd;
//	unsigned char *tmp_s;
	char *path;
	struct prng_context prng;

	memset(add_to_fast, 0, sizeof(add_to_fast));
	set_program_name(argc, argv);
	
	while ((opt = getopt(argc, argv, "f:")) != -1) {
		switch (opt) {
		case 'f':
			path = optarg;
			break;
		default: 
			print_used();
			exit(1);
		}
	}
	
	argc -= optind;
	argv += optind;

	
	if (process_server_config(path) != 1)
		return 1;
		
	res = entropy_pool_init(&fast_pool, options.nsources, options.entropy_hash);
	if (res == 0)
		printf("pool.nsources %d\n"
		       "pool.k %d\n"
		       "pool.hdesc->name %s\n\n",
		       fast_pool.nsources, 
		       fast_pool.k, 
		       fast_pool.hdesc->name);

	res = entropy_pool_set_k(&fast_pool, options.k);
	
	res = entropy_pool_init(&slow_pool, options.nsources, options.entropy_hash);
	if (res == 0)
		printf("slow_pool.nsoursec %d\n"
		       "slow_pool.k %d\n" 
		       "slow_pool.hdesc->name %s\n\n", 
		       slow_pool.nsources, 
		       slow_pool.k, 
		       slow_pool.hdesc->name);

	if (prng_cipher_init(options.prng_cipher, &prng)) {
		printf("prng.cipher_name %s \n"
		       "prng.cipher_len %d \n"
		       "prng.cipher_key_size %d \n",
		       prng.cdesc->name,
		       prng.cdesc->block_size,
		       prng.cdesc->key_size);
	} else {
		printf("Error of prng_cipher_init\n");
		return 1;
	}

	prng.cipher_ctx = prng.cdesc->context_new();

	if (prng_hash_init(options.prng_hash, &prng)) {
		printf("prng.hash_name %s\n"
		       "prng.digest_len %d\n",
		       prng.hdesc->name,
		       prng.hdesc->digest_len);
				
	} else {
		printf("Error of prng_hash_init\n");
		return 1;
	}

	res = entropy_pool_deinit(&fast_pool);

	if (res == 0)
		printf ("fast_pool_hdesc %p\n"
			"pool.nsources %d\n"
			"pool.k %d \n", 
			fast_pool.hdesc, 
			fast_pool.nsources, 
			fast_pool.k);

return 0;
}
