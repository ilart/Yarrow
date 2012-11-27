#include <ctype.h>

#include "common.h"
#include "macros.h"
#include "aes.h"
#include "aes-stream.h"

#define BUFFER_SIZE	4096

#define HAS_KEY_LENGTH	0x0001
#define HAS_KEY_FILE	0x0002
#define HAS_SYNC	0x0004
#define HAS_OUT_FILE	0x0008

#define OBLIG_OPTIONS	(HAS_KEY_FILE | HAS_SYNC)

static int		 decrypt_flag;
static aes_key_len_t	 key_len;
static aes_stream_mode_t mode;
static const char	*program_name;
static int		 optflags;
static char		*key_file;
static char		*out_file;
static u_int8_t		 syncmsg[16];

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
	       "Writes file transformed by AES (Rijndael) to standard output.\n"
	       "\n"
	       "Options: \n"
	       "  -e                   encryption mode (meaningful in asymmetric modes like CFB)\n"
	       "  -d                   decryption mode (asymmetric modes only)\n"
	       "  -k <secret-key-file> secret key file\n"
	       "  -l [128|192|256]     secret key length\n"
	       "  -m [cfb|ofb]         block cipher mode CFB (async) or OFB (sync)\n"
	       "  -s <hex-string>      initialization vector (IV) with each byte in hex\n"
	       "  -o <output-file>     output file\n"
	       "\n"
	       "  If no FILE provided or it is a -, then reads standard input. \n"
	       "  Default mode of operation is OFB (symmetric synchronous). \n"
	       "\n"
	       "Examples: \n"
	       " To encrypt or decrypt file using OFB mode and 256 bit key: \n"
	       "  %s -k key.bin -m ofb -l 256 -s 0001020304050607080a0b0c0d0e0f00 /etc/passwd > passwd.encr\n"
	       " To encrypt file using CFB mode and 128 bit key: \n"
	       "  %s -k key.bin -m cfb -e -l 256 -s 0001020304050607080a0b0c0d0e0f00 /etc/passwd > out.bin\n"
	       " To decrypt file using CFB mode and 128 bit key: \n"
	       "  %s -k key.bin -m cfb -d -l 256 -s 0001020304050607080a0b0c0d0e0f00 out.bin > passwd"
	       "\n"
	       "Please report bugs and errors to <sitkarev@unixkomi.ru>\n",
	       program_name, program_name, program_name, program_name);
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
	char *s;
	struct aes_context *ctx;
	struct aes_stream *stream;
	size_t bufsz;
	int i, c, opt, res;
	int infd, outfd;

	mode = AES_STREAM_MODE_DEFAULT;

	set_program_name(argc, argv);

	while ((opt = getopt(argc, argv, "edhk:l:m:o:s:")) != -1) {
		switch (opt) {
		case 'e':
			decrypt_flag = 0;
			break;
		case 'd':
			decrypt_flag = 1;
			break;
		case 'h':
			print_usage();
			exit(1);
		case 'k':
			key_file = optarg;
			optflags |= HAS_KEY_FILE;
			break;
		case 'l':
			switch (atoi(optarg)) {
			case 128:
				key_len = AES_KEY_128;
				break;
			case 192:
				key_len = AES_KEY_192;
				break;
			case 256:
				key_len = AES_KEY_256;
				break;
			default:
				printf("%s: invalid key length\n", program_name);
				print_usage();
				exit(1);
			}
			break;
		case 'm':
			if (strcasecmp(optarg, "cfb") == 0) {
				mode = AES_STREAM_MODE_CFB;
			} else if (strcasecmp(optarg, "ofb") == 0) {
				mode = AES_STREAM_MODE_OFB;
			} else {
				printf("%s: unsupported mode `%s'\n", program_name, optarg);
				print_usage();
				exit(1);
			}
			break;
		case 'o':
			out_file = optarg;
			optflags |= HAS_OUT_FILE;
			break;
		case 's':
			s = optarg;
			i = 0;
			while (*s != '\0') {
				int n;
				if (i >= ARRAY_SIZE(syncmsg))
					break;
				c = 0;
				for (n = 0; *s != '\0' && n < 2; n++) {
					if (*s >= '0' && *s <= '9') {
						c *= 16;
						c += *s - '0';
					} else if ((*s >= 'a' && *s <= 'f') ||
						   (*s <= 'A' && *s <= 'F')) {
						c *= 16;
						c += 10 + (tolower(*s) - 'a');
					} else {
						printf("%s: invalid hex digit in IV\n", program_name);
						exit(1);
					}
					++s;
				}
				syncmsg[i] = c;
				++i;
			}

			if (i < ARRAY_SIZE(syncmsg)) {
				printf("%s: not enough IV digits provided\n", program_name);
				exit(1);
			}

			optflags |= HAS_SYNC;
			break;
		default:
			print_usage();
			exit(1);
		}
	}

	argc -= optind;
	argv += optind;

	aes_init();

	if ((optflags & OBLIG_OPTIONS) != OBLIG_OPTIONS) {
		printf("%s: missing mandatory options\n", program_name);
		print_usage();
		exit(1);
	}

	ctx = aes_context_new();

	if (ctx == NULL) {
		fprintf(stderr, "%s: can't allocate AES context\n", program_name);
		exit(1);
	}

	if (key_file != NULL) {
		u_int32_t key[8];
		int nbytes[] = { 0, 16, 24, 32 };
		res = open_read_close(key_file, key, nbytes[key_len]);
		if (res != 0) {
			fprintf(stderr, "%s: can't read key file `%s': %s\n",
				program_name, key_file, strerror(errno));
			exit(1);
		}
		aes_set_key(ctx, key, key_len);
	}

	stream = aes_stream_create((aes_decrypt_func)aes_encrypt,
			(aes_encrypt_func)aes_decrypt, AES_BLOCK_NBYTES, ctx);

	if (stream == NULL) {
		fprintf(stderr, "%s: can't allocate AES stream\n", program_name);
		exit(1);
	}

	aes_stream_set_mode(stream, mode);

	if (optflags & HAS_SYNC) {
		aes_stream_set_iv(stream, syncmsg);
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

		res = read(infd, buf, bufsz);

		if (res == 0) 
			break;

		if (res == -1) {
#ifndef _WIN32
			if (errno == EINTR)
				continue;
#endif
			fprintf(stderr, "%s: read(): %s\n", 
				program_name, strerror(errno));
			goto out;
		}

		if (decrypt_flag)
			aes_stream_decrypt(stream, buf, res);
		else
			aes_stream_encrypt(stream, buf, res);

		res = full_write(outfd, buf, res);

		if (res == -1) {
			fprintf(stderr, "%s: write(): %s\n",
				program_name, strerror(errno));
			goto out;
		}
	}
out:
	aes_context_free(&ctx);
	aes_stream_destroy(&stream);

	if (outfd > 2)
		close(outfd);

	if (buf != NULL)
		free(buf);

	return 0;
}

