#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "md5.h"

#define BUFFER_LEN 32768

int
main(int argc, char *argv[])
{
	struct md5_context md5, *ctx;
	unsigned char digest[16];
	char *msg = "The quick brown fox jumps over the lazy dog";
	int i;

	ctx = &md5;

	if (argc >= 2) {
		unsigned char buf[BUFFER_LEN];
		int fd, res, n, eof;

		fd = open(argv[1], O_RDONLY);

		if (fd == -1) {
			fprintf(stderr, "can't open file `%s'\n", argv[1]);
			exit(1);
		}

		md5_context_init(ctx);

		eof = 0;

		for (;;) {
			n = 0;

			for (;;) {

				res = read(fd, buf+n, BUFFER_LEN-n);
		
				if (res == 0) {
					eof = 1;
					break;
				}
	
				if (res == -1) {
					if (errno == EINTR)
						continue;
					fprintf(stderr, "read() fd=%d: %s\n", fd, strerror(errno));
					exit(1);
				}

				n += res;

				if (n == BUFFER_LEN)
					break;
			}

			md5_update(ctx, buf, n);

			if (eof)
				break;
		}

		md5_final(ctx, digest);
		printf("%s: MD5=", argv[1]);
		for (i = 0; i < 16; i++)
			printf("%02x", digest[i]);
		printf("\n");

		close(fd);
	} else {
		md5_context_init(ctx);
		md5_update(ctx, msg, strlen(msg));
		md5_final(ctx, digest);

		printf("MD5(%s)=", msg);
		for (i = 0; i < 16; i++)
			printf("%02x", digest[i]);
		printf("\n");
	}

	return 0;
}

