/* sets nonblocking mode on socket descriptor */
void sock_nonblock(int sock)
{
	int res;
	int flags = 0;

	if ((flags = fcntl(sock, F_GETFL)) == -1)
		printf("sock_nonblock: F_GETFL sock=%d res=%d: %s",
				sock, flags, strerror(errno));
	if ((res = fcntl(sock, F_SETFL, flags | O_NONBLOCK)))
		printf("sock_nonblock: F_SETFL sock=%d res=%d: %s",
				sock, res, strerror(errno));
}

/* sets blocking mode on socket descriptor */
void sock_block(int sock)
{
	int res;
	int flags = 0;

	if ((flags = fcntl(sock, F_GETFL)) == -1)
		printf("sock_block: F_GETFL sock=%d res=%d: %s",
				sock, flags, strerror(errno));
	if ((res = fcntl(sock, F_SETFL, flags &= ~O_NONBLOCK)))
		printf("sock_block: F_SETFL sock=%d res=%d: %s",
				sock, res, strerror(errno));
}

/* closes listening PF_UNIX socket */
int sock_unix_close(int sock)
{
	int res;
	socklen_t slen;
	struct sockaddr_un addr;
	struct stat st;

	if (sock < 0)
		error("sock_unix_unlink: sock=%d", sock);

	slen = sizeof(struct sockaddr_un);
	res = getsockname(sock, (struct sockaddr *)&addr, &slen);
	if (res) {
		printf("sock_unix_unlink: getsockname()=%d: %s",
				res, strerror(errno));
		return -1;
	}
	if (addr.sun_family != PF_UNIX || !addr.sun_path[0])
		return -1;
	do {
		res = close(sock);
	} while (res == -1 && errno == EINTR);
	res = stat(addr.sun_path, &st);
	if (res) {
		printf("sock_unix_unlink: stat()=%d: %s",
				res, strerror(errno));
		return -1;
	}
	if (((S_IFSOCK & st.st_mode) == 0) || unlink(addr.sun_path)) {
		printf("sock_unix_unlink: unlink() failed or not socket");
		return -1;
	}
	return 0;
}

/* creates PF_UNIX socket ready to accept connections */
int sock_unix_listen(const char *path)
{
	int res, sock;
	struct sockaddr_un addr;

	if (!path)
		error("sock_unix_listen: path NULL");

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = PF_UNIX;
	xstrncpy(addr.sun_path, path, UNIX_PATH_MAX);
	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		printf("sock_unix_listen: PF_UNIX '%s' socket error: %s",
				path, strerror(errno));
		return -1;
	}
	res = bind(sock, (struct sockaddr *) &addr, sizeof(addr));
	if (res == -1) {
		printf("sock_unix_listen: can't bind() to '%s': %s",
				path, strerror(errno));
		do {
			res = close(sock);
		} while (res == -1 && errno == EINTR);
		return -1;
	}
	res = listen(sock, 10);
	if (res == -1) {
		printf("sock_unix_listen: can't listen() on '%s': %s",
				path, strerror(errno));
		do {
			res = close(sock);
		} while (res == -1 && errno == EINTR);
		res = unlink(addr.sun_path);
		if (res)
			printf("sock_unix_listen: can't unlink '%s': %s",
					addr.sun_path, strerror(errno));
		return -1;
	}
	return sock;
}

char *xstrncpy(char *dst, const char *src, size_t max)
{
	size_t len;

	if (!dst || !src)
		error("xstrncpy: dst or src NULL");

	if (max > SSIZE_MAX)
		error("xstrncpy: max %lu bytes", (unsigned long) max);

	len = strnlen(src, max-1);
	memcpy(dst, src, len);
	dst[len] = '\0';

	return dst;
}

