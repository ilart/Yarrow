#include "common.h"
#include "macros.h"
#include "gost.h"

#define BUFFER_SIZE	4096

#define HAS_SBOX_FILE	0x0001
#define HAS_KEY_FILE	0x0002
#define HAS_SYNC	0x0004
#define HAS_OUT_FILE	0x0008

#define OBLIG_OPTIONS	(HAS_KEY_FILE | HAS_SYNC)

static const char	*program_name;
static int		optflags;
static char		*sbox_file;
static char		*key_file;
static char		*out_file;
static u_int32_t	syncmsg[2];

int
full_read(int fd, void *buf, size_t size)
{
	size_t left;
	int res;

	left = size;

	while (left) {
#ifdef _WIN32
		res = read(fd, buf, left);

		if (res == -1)
			return -1;
#else
		res = read(fd, buf, left);

		if (res == -1) {
			if (errno != EINTR)
				return -1;
			continue;
		}
#endif
		if (res == 0)
			break;
		left -= res;
		buf += res;
	}

	return left;
}

int
full_write(int fd, const void *buf, size_t size)
{
	size_t left;
	int res;

	left = size;

	while (left) {
#ifdef _WIN32
		res = write(fd, buf, left);

		if (res == -1)
			return -1;
#else
		res = write(fd, buf, left);
		if (res == -1) {
			if (errno != EINTR)
				return -1;
			continue;
		}
#endif
		if (res == 0)
			break;
		left -= res;
		buf += res;
	}

	return left;
}

int
open_read_close(const char *file, void *buf, size_t len)
{
	int fd, res;
	int save_errno;

#ifdef _WIN32
	fd = open(file, O_RDONLY | O_BINARY);
#else
	fd = open(file, O_RDONLY);
#endif
	if (fd == -1)
		return -1;
	res = full_read(fd, buf, len);
	save_errno = errno;
	close(fd);
	errno = save_errno;
	return res;
}

static void
print_usage()
{
	printf("Usage: %s [OPTIONS] [FILE]\n"
	       "Writes file transformed by GOST 28147-89 to standard output.\n"
	       "\n"
	       "Options: \n"
	       "  -b <sbox-file>       substitution box file\n"
	       "  -k <secret-key-file> secret key file\n"
	       "  -s <SYNC0,SYNC1>     inital gamma synchronisation sequence (hex)\n"
	       "  -o <output-file>     output file\n"
	       "\n"
	       "  If no FILE provided or it is a -, then reads standard input. \n"
	       "\n"
	       "Examples: \n"
	       "  %s -k key.bin -s 0x01020304,0xdeadbeaf /etc/passwd > passwd.encr\n"
	       "\n"
	       "Please report bugs and errors to <sitkarev@unixkomi.ru>\n",
	       program_name, program_name);
}

static void
set_program_name(int argc, char *argv[])
{
	char *s;

	program_name = ((s = strrchr(argv[0], '/')) != NULL) ? ++s : argv[0];
}

int
main(int argc, char *argv[])
{
#ifdef _WIN32
	struct _stat sti, sto;
#else
	struct stat sti, sto;
#endif
	unsigned char *buf;
	char *s, *cp;
	struct gost_context *ctx;
	size_t bufsz;
	int opt, res;
	int infd, outfd;

	set_program_name(argc, argv);

	while ((opt = getopt(argc, argv, "b:hk:s:o:")) != -1) {
		switch (opt) {
		case 'b':
			sbox_file = optarg;
			optflags |= HAS_SBOX_FILE;
			break;
		case 'h':
			print_usage();
			exit(1);
		case 'k':
			key_file = optarg;
			optflags |= HAS_KEY_FILE;
			break;
		case 'o':
			out_file = optarg;
			optflags |= HAS_OUT_FILE;
			break;
		case 's':
			s = optarg;
			syncmsg[0] = strtoul(s, &cp, 16);
			if (cp != s && *cp == ',') {
				s = ++cp;
				syncmsg[1] = strtoul(s, NULL, 16);
				optflags |= HAS_SYNC;
			} else {
				optflags &= ~HAS_SYNC;
			}
			break;
		default:
			print_usage();
			exit(1);
		}
	}

	argc -= optind;
	argv += optind;

	if ((optflags & OBLIG_OPTIONS) != OBLIG_OPTIONS) {
		printf("%s: missing mandatory options\n", program_name);
		print_usage();
		exit(1);
	}

	ctx = gost_context_new();

	if (ctx == NULL) {
		fprintf(stderr, "%s: can't allocate GOST context\n", program_name);
		exit(1);
	}

	if (sbox_file != NULL) {
		u_int8_t sbox[128];
		res = open_read_close(sbox_file, sbox, sizeof(sbox));
		if (res != 0) {
			fprintf(stderr, "%s: can't read sbox file `%s': %s\n",
				program_name, sbox_file, strerror(errno));
			exit(1);
		}
		gost_set_sbox(ctx, sbox);
	} else {
		gost_set_sbox(ctx, NULL);
	}

	if (key_file != NULL) {
		u_int32_t key[8];
		res = open_read_close(key_file, key, sizeof(key));
		if (res != 0) {
			fprintf(stderr, "%s: can't read key file `%s': %s\n",
				program_name, key_file, strerror(errno));
			exit(1);
		}
		gost_set_key(ctx, key);
	}

	if (optflags & HAS_SYNC) {
		gost_set_sync(ctx, syncmsg);
	} else {
		fprintf(stderr, "%s: warning: no sync message\n", program_name);
	}

	if (argc <= 0 || (argv[0][0] == '-' && argv[0][1] == '\0')) {
		infd = STDIN_FILENO;
	} else if (argc > 0) {
#ifdef _WIN32
		infd = open(argv[0], O_RDONLY | O_BINARY);
#else
		infd = open(argv[0], O_RDONLY);
#endif
		if (infd == -1) {
			fprintf(stderr, "%s: can't open input file `%s': %s\n",
				program_name, argv[0], strerror(errno));
			exit(1);
		}
	}

	if (out_file != NULL) {
		int oflags;
#ifdef _WIN32
		oflags = O_WRONLY | O_CREAT | O_TRUNC | O_BINARY;
#else
		oflags = O_WRONLY | O_CREAT | O_TRUNC;
#endif
		outfd = open(out_file, oflags, S_IRUSR|S_IWUSR);
		if (outfd == -1) {
			fprintf(stderr, "%s: can't open output file `%s': %s\n",
				program_name, argv[0], strerror(errno));
			exit(1);
		}
	} else {
		outfd = STDOUT_FILENO;
	}

	/* Ensure that outfd and infd are different files. */
#ifdef _WIN32
	if (_fstat(outfd, &sto) == -1 || _fstat(infd, &sti) == -1) {
#else
	if (fstat(outfd, &sto) == -1 || fstat(infd, &sti) == -1) {
#endif
		fprintf(stderr, "%s: can't stat input or output file\n", program_name);
		exit(1);
	}

	if (S_ISBLK(sto.st_mode) && 
	    ((sto.st_dev == sti.st_dev) && (sto.st_ino == sti.st_ino))) {
		fprintf(stderr, "%s: input and output is the same file\n", program_name);
		exit(1);
	}

#ifdef _WIN32
	bufsz = BUFFER_SIZE;
#else
	/* Set buffer to device specific size. */
	if (S_ISBLK(sti.st_mode))
		bufsz = sti.st_blksize;
	else
		bufsz = BUFFER_SIZE;
#endif

	buf = malloc(bufsz);
	if (buf == NULL) {
		fprintf(stderr, "%s: can't alloc buf\n", program_name);
		exit(1);
	}

	for (;;) {
#ifndef _WIN32
read_again:
#endif
		res = read(infd, buf, bufsz);

		if (res == 0) 
			break;

		if (res == -1) {
#ifndef _WIN32
			if (errno == EINTR)
				goto read_again;
#endif
			fprintf(stderr, "%s: read(): %s\n", 
				program_name, strerror(errno));
			exit(1);
		}


		gost_apply_gamma(ctx, buf, res);

		res = full_write(outfd, buf, res);

		if (res == -1) {
			fprintf(stderr, "%s: write(): %s\n",
				program_name, strerror(errno));
			exit(1);
		}
	}
	
	return 0;
}

