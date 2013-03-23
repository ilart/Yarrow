#include "stdio.h"
#include "stdlib.h"

typedef struct {
	tok_id id;
	char *name;
} attribute_table;

attribute_table attr[] = { 
	{ATT_PRNG_CIPHER, "prng_cipher"},
	{ATT_PRNG_HASH, "prng_hash"},
	{ATT_ENTROPY_HASH, "entropy_hash"},
	{ATT_GATE, "gate"},
	{ATT_NSOURCES, "nsources"},
	{ATT_K, "k"}
};

static void print_used()
{
	printf("Usage: %s [OPTIONS] [FILE]\n"
	       "Options: \n"
	       "  -f <config-file>		path config file\n"
	       "  --prng_cipher <cipher-name>	cipher name for prng\n"
	       "  --prng_hash <hash-name>	hash name for prng\n"
	       "  --entropy_hash <hash-name>	hash name for entropy pool\n"
	       "  --gate <param>		value of gate\n"
	       "  --time <param>		value of time\n"
	       "\n"
	       "If no FILE provided, then value will default\n",
	       program_name);
}

static void set_program_name()
{
	char *s;

	program_name = ((s = strrchr(argv[0], '/')) != NULL) ? ++s : argv[0];
}

int parce_attr(const char *path)
{
	int fd, res;
	char buf[128];

	fd = fopen(path, r);
	
	while (fgets(buf, sizeof[buf], fd) != NULL) {
				
	}
}

int main(int argc, char **argv)
{
	int opt, res;
	char *path;

	set_program_name();
	
	while (opt = getopt(argc, argv, "f") != -1) {
		switch (opt) {
		case 'f':
			path = optarg;
			break;
		default: 
			print_usage();
			exit(1);
		}
	}
	
	argc -= optind;
	argv += optind;
	
	res = parce_attr(path);

	/*when call init functions*/

return 0;
}
