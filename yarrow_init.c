#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

#define ATT_PRNG_CIPHER 1
#define ATT_PRNG_HASH 2
#define ATT_ENTROPY_HASH 3
#define ATT_GATE 4
#define ATT_NSOURCES 6
#define ATT_K 5

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
	char *prng_cipher;
	char *prng_hash;
	char *entropy_hash;
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
	int i, res, value, linenum;
	FILE *fd;
	char *line, *arg;
	ServerOpCodes opcode;

	linenum = 1;
	line = calloc(128, 1);
	
	fd = fopen(filename, "rw");
	
	while (fgets(line, 127, fd) != NULL) {
		linenum++;

		if ((arg = strdelim(&line)) == NULL)
			return 0;
		printf("arg = %s,\n", arg);
		
		/* Ignore leading whitespace */
		if (*arg == '\0')
			arg = strdelim(&line);

		if (!arg || !*arg || *arg == '#')
		return 0;

		for (i = 0; attr_table[i].name; i++) {
			if (strcasecmp(arg, attr_table[i].name) == 0) {
				opcode = attr_table[i].opcode;
			}
		}

		switch(opcode) {
		case PrngCipher:
			arg = strdelim(&line);
			options.prng_cipher = arg;
			break;
		case PrngHash:
			arg = strdelim(&line);
			options.prng_hash = arg;
			break;
		case EntropyHash:
			arg = strdelim(&line);
			options.entropy_hash = arg;
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
	}
	return 0;
}

int main(int argc, char **argv)
{
	int opt, res;
	char *path;

	set_program_name(argc, argv);
	
	while ((opt = getopt(argc, argv, "f:")) != -1) {
		switch (opt) {
		case 'f':
			printf("flag optarg %s\n", optarg);
			path = optarg;
			break;
		default: 
			print_used();
			exit(1);
		}
	}
	
	argc -= optind;
	argv += optind;

	printf("path %s \n", path);
	res = proccess_server_config(path);

	/*when call init functions*/

return 0;
}
