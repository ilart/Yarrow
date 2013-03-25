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

typedef struct {
	int id;
	char *name;
} attribute_table;

static const char	*program_name;

attribute_table attr_table[] = { 
	{ATT_PRNG_CIPHER, "prng_cipher"},
	{ATT_PRNG_HASH, "prng_hash"},
	{ATT_ENTROPY_HASH, "entropy_hash"},
	{ATT_GATE, "gate"},
	{ATT_NSOURCES, "nsources"},
	{ATT_K, "k"}
};

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

char *get_arg(char **line)
{
	char *old;

	old = *line;
	*line = strpbrk(*line, " \t\n=");
	if (*line == NULL) 
		return old;

	*line[0] = '\0';

	return old;
	
}

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

int parce_attr(const char *path)
{
	int i, res;
	FILE *fd;
	char *line;

	line = calloc(128, 1);
	
	fd = fopen(path, "rw");
	
	while (fgets(line, sizeof(line), fd) != NULL) {
		line = get_arg(&line);
		printf("line = %s,\n", get_arg(&line));
		printf("line = %s,\n", get_arg(&line));
		printf("line = %s,\n", get_arg(&line));
		printf("line = %s,\n", get_arg(&line));
		/*
		for (i = 0; attr_table[i].name; i++) {
			if (strcasecmp(line, attr_table[i].name) == 0) {
				*flags 
			}
*/		}
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
	res = parce_attr(path);

	/*when call init functions*/

return 0;
}
