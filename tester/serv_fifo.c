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
#include <signal.h>
#include <sys/types.h>

#define SSIZE_MAX	LONG_MAX
#define FIFO_PATH	"/home/il/prog/yarrow/tester/fifo"
#define PACKET_SIZE	128	
#define NELEMS(x)	(sizeof(x)/sizeof(x[0]))

struct entropy_source {
	int id;
	char *path;
	int estimate;
	int len;
} entropy_src[32];


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
				printf("read() returned %d: %s", res, strerror(res));
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

void
dec_to_hex(int val, char *str)
{
	int i, base, t, d, r;
	base = 16;
	d = val;
	r = 1;
	for (i = 0; r != 0; i++) {
		r = d / base;
		t = d % base;
		printf("r = %d, t = %d\n", r,t);
		if (t < 10)
			str[i] = t + '0';
		else
			str[i] = t - 10 + 'A';

		printf("%c ", str[i]);
		d = r;
	} 
}

int
accumulate_samples(int id) 
{
	int res, left, fifo_fd, fd, used;
	char buf[PACKET_SIZE];		//Our packet will have max size of 128
						//including id and special characters '\r\n'
	fd 	= open(entropy_src[id].path, O_RDONLY);
	fifo_fd = open(FIFO_PATH, O_NONBLOCK | O_WRONLY);
	
	printf("id %d pid %d: open fifo_fd %d, src_fd %d\n", id, getpid(), fifo_fd, fd);

	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		printf("signal returned SIG_ERR\n");

	used = sprintf(buf, "%d", id);
	left = PACKET_SIZE - used - strlen("\r\n");

	while (left) {
		res = read(fd, buf + used, left);
		if (res == -1) {
			if (errno == EINTR)
				continue;
			else {
				printf("read returned -1: %s\n", strerror(res));
				exit(1);
			}
		} else {
			left -= res;
			used += res;
		}
	}
	
	sprintf(buf+used, "\r\n");

	printf("accumulate buf %s\n"
	       "id %d\n", buf, atoi(buf));

	res = write(fifo_fd, buf, PACKET_SIZE);
	if (res == -1) {
		printf("write returned %d: %s\n", res, strerror(res));
		exit(1);
	}
/*

	while (left--) {
		res = read(fd, buf, sizeof(buf) - 4);
		if (res > 0) {
			buf[res] = id;
			buf[res+1] = '\r';
			buf[res+2] = '\n';
			buf[res+3] = '\0';

			printf("pid %d: I send packet %d byts,"
			       "strlen %d, from %s\n",
			       getpid(), res,
			       strlen(buf), entropy_src[id].path);
//			build_packet(buf); 
			//write(fifo_fd, buf, sizeof(buf));
		} else if (res < 0 && errno == EINTR) {
			continue;
		} else if (res < 0) {
			printf("Read returned %d: %s \n",
			       res, strerror(res));
			exit(1);
		}
		res = write(fifo_fd, buf, sizeof(buf));
		if (res == -1) {
			printf("write returned %d: %s\n", res, strerror(res));
			exit(1);
		}
	}
*/	
	close(fd);
	close(fifo_fd);

	return 0;
}

int 
accumulate_entropy()
{
	int fd, res, left, flag;
	char *cp, buf[PACKET_SIZE];

	fd = poll_fd[0].fd;
	
	left = PACKET_SIZE;
	flag = 0;

	while (left) {
		res = read(fd, buf + flag, left);
		if (res == -1) {
			printf("read returned %d: %s\n", res, strerror(res));
			exit(1);
		}
		
		printf("recived entropy %d byts: %s, atoi %d\n", res, buf, atoi(buf));

		flag += res;
		left -= res;
		printf("id %d\n", atoi(buf));
		buf[flag] = '\0';
		cp = buf;
			
		while (*cp != '\0') {
			if (cp[0] == '\r' && cp[1] == '\n') {
				*cp = '\0';
				printf("End \n");
				return 0;
			} else {
				cp++;
			}
		}
	}

	return 1;
}

void
init_peer(int fd, int i) 
{
	poll_fd[i].fd = fd;
	poll_fd[i].events = (POLLIN | POLLPRI);

	peer_ctx[i].sfd = fd;
	peer_ctx[i].bufused = 0;
}

int main (int argc, char **argv) 
{
	int pid, nsources, left, fifo_fd, res, i, nelems;

//--------------- This part of code will produce entropy_pool_init() fuction
	entropy_src[0].id = 120;
	entropy_src[0].path = "/dev/random";
	entropy_src[0].estimate = 0.4;
	entropy_src[0].len = 100;

	entropy_src[1].id = 1;
	entropy_src[1].path = "/dev/urandom";
	entropy_src[1].estimate = 0.5;
	entropy_src[1].len = 120;

	entropy_src[2].id = 2;
	entropy_src[2].path = NULL;
	entropy_src[2].estimate = 0.8;
	entropy_src[2].len = 120;
//---------------------------------------------------------------------------

	res = mkfifo(FIFO_PATH, S_IRUSR | S_IWUSR | S_IWGRP);
	if (res == -1 && errno != EEXIST) {
		printf("mkfifo returned %d: %s\n", res, strerror(res));
		exit(1);
	}
		
	printf("mkfifo %d\n", res);
	fifo_fd = open(FIFO_PATH, O_NONBLOCK | O_RDONLY);
	if (fifo_fd == -1)
		printf("open returned %d: %s\n",
			fifo_fd, strerror(fifo_fd));

	nsources = 1; // this value will be taken from entropy_pool.nsources
	printf("open fifo %d\n", fifo_fd);

	// create children for accumulate entropy from i source
	// All information about source will be obtained from config file.
	for (i = 0; i < nsources; i++) {
		switch (pid = fork()) {
		case -1:
			printf("Fork returned %d: %s\n",
			       pid, strerror(pid));
			exit(1);
		case 0:
			accumulate_samples(i); 
			return 0;
		default:
			break;
		}
	}
		
	poll_fd = calloc(1, sizeof(struct pollfd));
	if (poll_fd == NULL) {
		perror("Calloc returned NULL.");
		exit(1);
	}

	peer_ctx = calloc(1, sizeof(struct peer));
	if (peer_ctx == NULL) {
		perror("Calloc returned NULL");
		exit(1);
	}
	
	nelems = 1;

	init_peer(fifo_fd, 0);
	
	left = 10;	
	printf("parent: open fifo_fd %d\n", fifo_fd);

	while (left) {
		printf("left %d\n", left);
		res = poll(poll_fd, nelems, -1);
		if (res == -1 && errno != EINTR) {
			printf("poll returned %d: %s\n",
			      res, strerror(errno));
			break;
		}
		
		if (poll_fd[0].revents & POLLIN) {
//			accept_connect(&nelems);
			if (accumulate_entropy()) 
				printf("Can not find id in packet\n");

			poll_fd[0].revents = 0;
		} 
 		
//		process_events(nelems); 
		left--;
	}	
	
	close(fifo_fd);
	unlink("./fifo");
return 0;
}
