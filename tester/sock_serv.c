#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <linux/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/poll.h>
#include <time.h>
#include <limits.h>
#include <sys/types.h>

#define SSIZE_MAX	LONG_MAX
#define FIFO_PATH	"/var/run/yarrow_fifo"
#define PACKET_SIZE	512
#define NELEMS(x)	(sizeof(x)/sizeof(x[0]))

struct entropy_source {
	int id;
	char *path;
	double estimate;
	int len;
} entropy_src[2];



struct peer {
	int sfd;
	char buf[LINE_MAX+1];
	int bufused;
} *peer_ctx;

struct pollfd *poll_fd;

int sock_unix_listen(const char *path)
{
	int res, sock, len;
	struct sockaddr_un addr;

	if (!path)
		perror("sock_unix_listen: path NULL");

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = PF_UNIX;
	len = strlen(path);
	memcpy(addr.sun_path, path, len);
	addr.sun_path[len] = '\0';
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


/* closes listening PF_UNIX socket */
int sock_unix_close(int sock)
{
	int res;
	socklen_t slen;
	struct sockaddr_un addr;
	struct stat st;

	if (sock < 0)
		printf("sock_unix_unlink: sock=%d", sock);

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

void
write_fd(int fd, struct peer *p)
{
	int res, left;
	left = p->bufused;

	p->bufused = 0;

	while (left) {
		res = write(fd, p->buf+p->bufused, left);
		if (res == -1 && errno != EINTR) {
			printf("Write returned %d: %s\n", res, strerror(res));
			exit(1);
		}
		
		p->bufused += res;
		left -= res;
	}
	return;
}

int 
read_fd(int fd, struct peer *p) 
{
	int res;
	char *cp;
	res = 0;

	for (;;) {
		res = read(fd, (p->buf)+(p->bufused), LINE_MAX-(p->bufused));
		if (res > 0) {
			cp = p->buf;
			p->bufused += res;
			p->buf[p->bufused] = '\0';
			while (*cp != '\0') {
				if (cp[0] == '\r' && cp[1] == '\n') {
					*cp = '\0';
					return 0;
				} else {
					cp++;
				}
			}
		} else if (res == 0) {
			p->sfd = -1;
			return 0;
		} else {
			if (errno == EAGAIN)
				break;
			else {
				printf("read returned %d: %s", res, strerror(res));
				exit(1);
			}
		}
	}
		return 1;
}

void xfree(void *ptr)
{
	if (ptr == NULL)
		printf("xfree NULL pointer");

	free(ptr);
}

void *xrealloc0(void *mem, size_t old_size, size_t new_size)
{
	void *ptr;

	if (mem == NULL && old_size)
		perror("xrealloc0 old_size != 0 on NULL memory");

	if (new_size == 0 || new_size > SSIZE_MAX)
		printf("xrealloc0 requested %lu bytes", (unsigned long) new_size);

	if (mem == NULL)
		ptr = malloc(new_size);
	else {
		ptr = realloc(mem, new_size);
		printf("Realloc new_size %d old_size %d\n", (int) new_size, (int) old_size);
	}
	if (ptr == NULL) {
		printf("xrealloc0 out of memory allocating %lu bytes",
				(unsigned long) new_size);
	}

	if (new_size > old_size)
		memset(ptr + old_size, 0, new_size - old_size);

	printf("xrealloc: old ptr %p new ptr %p\n", mem, ptr);
	return ptr;
}

void 
process_events(int count) 
{
	int idx, res;

	//printf("count of desc %d\n", count);
	for (idx = 1; idx < count; idx++) {
		if (poll_fd[idx].revents & (POLLIN|POLLPRI)) {

			res = read_fd(poll_fd[idx].fd, &peer_ctx[idx]);
			if (res == 0 && peer_ctx[idx].sfd != -1)
				write_fd(poll_fd[idx].fd, &peer_ctx[idx]);
			else if (res == 0 && peer_ctx[idx].sfd == -1) {
				close(poll_fd[idx].fd);
				poll_fd[idx].fd = -1;
				poll_fd[idx].events = 0;
				poll_fd[idx].revents = 0;
				continue;
			} else 
				continue;

			printf("revents %d, Client send: %s\n",
			       poll_fd[idx].revents, peer_ctx[idx].buf);
		}
		if (poll_fd[idx].revents & (POLLERR|POLLNVAL)) {
			printf("we recived %d event from %d desc\n",
			       poll_fd[idx].revents, poll_fd[idx].fd);
			poll_fd[idx].fd = -1;
			poll_fd[idx].events = 0;
			poll_fd[idx].revents = 0;
		}

	}
}

int 
find_unused_fd(int *count)
{
	int i, size;

	for (i = 0; i < *count; i++) {
		if (poll_fd[i].fd == -1 && poll_fd[i].events == 0) {
			assert(peer_ctx[i].sfd == -1);
			return i;
		}
	}

	size = *count * sizeof(struct pollfd);
	poll_fd = xrealloc0(poll_fd, size, size + sizeof(struct pollfd));
	
	size = *count * sizeof(struct peer);
	printf("xrealloc peer size %d \n ", size);
	peer_ctx = xrealloc0(peer_ctx, size, size + sizeof(struct peer));

	*count += 1;
	return *count-1;
}

void
accept_connect(int *nelems)
{
	int client_fd, idx;
	struct sockaddr saddr;
	socklen_t slen;

	while (1) {
		client_fd = accept(poll_fd[0].fd, &saddr, &slen);
		if (client_fd > 0) {
			idx = find_unused_fd(nelems);
			poll_fd[idx].fd = client_fd;
			poll_fd[idx].events = (POLLIN|POLLPRI);
		
			peer_ctx[idx].sfd = client_fd;
			peer_ctx[idx].bufused = 0;
		
			sock_nonblock(client_fd);
			printf("we recive connect fd=%d nelems %d\n",
			       client_fd, *nelems);
		} else if (client_fd == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			return;
		} else if (client_fd == -1 && errno != EINTR) {
			printf("accept returned %d: %s", client_fd, strerror(client_fd));
			exit(1);	
		}
	}
	return;
}

int
accumulate_samples(int id) 
{
	int fd, res, left, fifo_fd;
	char buf[PACKET_SIZE-4];	//Our packet will have max size of 128
				//including id and special characters '\r\n'
	left = 3;
	fd = open(entropy_src[id].path, S_IRUSR);
	fifo_fd = open(FIFO_PATH, S_IWUSR);

	while (left--) {
		res = read(fd, buf, sizeof(buf));
		if (res == sizeof(buf)) {
			buf[res] = id;
			buf[res+1] = '\r';
			buf[res+2] = '\n';
			buf[res+3] = '\0';

			printf("pid %d: I send packet %d byts, %s strlen %d\n", getpid(), res, buf, strlen(buf));
//			build_packet(buf); 
		} else if (res < 0 && errno == EINTR) {
			continue;
		} else if (res < 0) {
			printf("Read returned %d: %s \n",
			       res, strerror(res));
			exit(1);
		}
		
		res = write(fifo_fd, buf, strlen(buf));
		printf("write %d bytes\n", res);
	}
	
	close(fd);
	close(fifo_fd);

	return 0;
}

int 
accumulate_entropy (char *buf)
{
	int fd, len, id;

	fd = poll_fd[1].fd;
	
	read(fd, buf, PACKET_SIZE)
	if (res > 0) {
		len = strlen(buf);
		assert(buf[len-1] == '\n' && buf[len-2] == '\r');
		id = buf[len-3];
		printf("id src %d\n", id);
	} else if (res < 0) {
		printf("read returned %d: %s\n", res, strerror(res));
		exit(1);
	}

	return 0;
}

int main (int argc, char **argv) 
{
	int server_fd, fifo_fd, res, i, nelems;
	char buf[LINE_MAX], packet[PACKET_SIZE];
	
	entropy_src[0].id = 0;
	entropy_src[0].path = "/dev/random";
	entropy_src[0].estimate = 0.4;
	entropy_src[0].len = 100;

	entropy_src[0].id = 1;
	entropy_src[0].path = "/dev/urandom";
	entropy_src[0].estimate = 0.5;
	entropy_src[0].len = 120;

	entropy_src[0].id = 2;
	entropy_src[0].path = NULL;
	entropy_src[0].estimate = 0.8;
	entropy_src[0].len = 120;

	mkfifo(FIFO_PATH, 0777);
	fifo_fd = open(FIFO_PATH, O_NONBLOCK);
	if (fifo_fd == -1)
		printf("open returned %d: %s\n",
			fifo_fd, strerror(fifo_fd));

	nsources = 2; // this value will be taken from entropy_pool.nsources

	// create children for accumulate entropy from i source
	// All information about source will be obtained from config file.
	for (i = 0; i < nsources; i++) {
		if ((pid = fork()) < 0) {
			printf("Fork returned %d: %s\n",
			       pid, strerror(pid));
			exit(1);
		} else if (pid == 0) {
			accumulate_samples(i); 
	}
		
	server_fd = sock_unix_listen("/var/run/yarrow.socket");
	if (server_fd <= 0) {
		perror("Sock unix listen");
		exit(1);
	}

	printf("server_fd %d\n", server_fd);
	sock_nonblock(server_fd);

	poll_fd = calloc(2, sizeof(struct pollfd));
	if (poll_fd == NULL) {
		perror("Calloc returned NULL.");
		exit(1);
	}

	poll_fd[0].fd = server_fd;
	poll_fd[0].events = POLLIN;
	poll_fd[1].fd = fifo_fd;
	poll_fd[1].events = (POLLIN|POLLPRI);

	peer_ctx = calloc(2, sizeof(struct peer));
	if (peer_ctx == NULL) {
		perror("Calloc returned NULL");
		exit(1);
	}
	
	peer_ctx[0].sfd = server_fd;
	peer_ctx[0].bufused = 0;
	peer_ctx[1].sfd = fifo_fd;
	peer_ctx[1].bufused = 0;

	nelems = 2;
	i = 0;
	
	while (1) {
		res = poll(poll_fd, nelems, -1);
		if (res > 0) {
			if (poll_fd[0].revents & POLLIN) {
				accept_connect(&nelems);
			} else if (poll_fd[1].revents & POLLIN) {
				accumulate_entropy(packet);	
			}
 		
			process_events(nelems); 
		} else if (res < 0 && errno != EINTR) {
			printf("poll returned %d: %s\n",
			      res, strerror(errno));
			break;
		} 
	}	
	
	close(server_fd);
	unlink("/var/run/yarrow.socket");
return 0;
}
