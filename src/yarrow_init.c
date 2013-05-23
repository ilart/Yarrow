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
#include "sock-unix.h"
#include "yarrow_init.h"

#define SSIZE_MAX	LONG_MAX

#define NELEMS(x)	(sizeof(x)/sizeof(x[0]))

typedef enum {
	PrngCipher, PrngHash,
	EntropyHash, 
	TimeParam, GateParam,
	Nsources,
	K,
	path_to_src,
	estimate,
	fthreshold,
	sthreshold
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
	{"k", K},
	{"path_to_src", path_to_src},
	{"estimate", estimate},
	{"fthreshold", fthreshold},
	{"sthreshold", sthreshold}
};

typedef struct {
	char prng_cipher[16];
	char prng_hash[16];
	char entropy_hash[16];
	int time_param;
	int gate_param;
	int nsources;
	int k;
	char path_to_src[MAX_SOURCES][MAX_LENGHT_NAME]; //paths to sources 
	double estimate[MAX_SOURCES];
	float fthreshold[MAX_SOURCES];
	float sthreshold[MAX_SOURCES];
}	Options;


Options options;


struct peer {
	int sfd;
	unsigned char buf[LINE_MAX+1];
	int bufused;
} *peer_ctx;

struct pollfd *poll_fd;

int received_sigterm = 0;
int received_sigchld = 0;

/*void
write_fd(int fd, struct peer *p, int left)
{
	int res;

	p->bufused = 0;

	return;
}
*/

int 
read_request(int fd, struct peer *p) 
{
	int res;
	unsigned char *cp;
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
					//printf("\n Client send: %s\n", p->buf);
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
				p->sfd = -1;
				return 0;
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

void convert_to_hex(unsigned char *src, unsigned char *dst, int n) 
{
	int k, res;

	for (k = 0; k < n; k++) {
		res = src[k];
		if (res < 16 && res > 0)
			sprintf(dst+ k*2, "0%x", src[k]);
		else
			sprintf(dst + k*2, "%x", src[k]);
	}
}

void
build_send_replay(struct peer *p, struct prng_context *prng)
{
	int n, req, res, i;
	size_t size;
	unsigned char packet[LINE_MAX+1], *ptr;
	
	req = atoi(p->buf) * 2;  /*we will send plain-text 
				   and one character - one byte*/
	if (req <= 0 ) {
		printf("Bad request: user requested a negative number\n");
		return;
	}
	printf("Client request %d\n", req);

	while (req) {
		n = prng->used-1 > req ? req : prng->used-1;
		n = n > LINE_MAX/2 ? LINE_MAX/2 : n; 

		printf("\n\n n = %d used = %d, req = %d\n\n", n, prng->used, req);
		req -= n; 
		prng->used -= n;
			
		memcpy(p->buf, prng->random_storage + prng->used, n);
		memset(prng->random_storage + prng->used, 0, n);	
		printf("Random storage\n");
//		for (i = 0; i < 500; i++)
//			printf("%x",prng->random_storage[i]);
			//
		convert_to_hex(p->buf, packet, n);
		printf("Server send to client\n");
		for (i = 0; i < n; i++)
			printf("%x",p->buf[i]);
		res = 0;		
		ptr = packet;
		
		printf("SEND %d byts\n", n);

		while (n) {
			res = write(p->sfd, ptr, n);
			if (res == -1 && errno != EAGAIN) {
				printf("Write returned %d: %s\n", res, strerror(res));
				req = 0;
				break;
			} 
				
			n -= res;
			ptr += res;
		}

		if (prng->used < 512) { 
			printf("FILL THE BUFFER\n\n\n");
			size = STORAGE_SIZE - prng->used;
			prng_encrypt(prng, prng->random_storage, &size);
		}
	}
	
	return;
}

void 
process_events(int count, struct prng_context *prng) 
{
	int idx, res;

	for (idx = 2; idx < count; idx++) {
		printf("flag in proccess_events for: idx = %d\n", idx);
		if (poll_fd[idx].revents & (POLLIN|POLLPRI)) {

			res = read_request(poll_fd[idx].fd, &peer_ctx[idx]);
			if (res == 0 && peer_ctx[idx].sfd != -1) {
				printf("flag in proccess_events: befor build_send_replay\n");
				build_send_replay(&peer_ctx[idx], prng);
				printf("flag in proccess_events: after build_send_replay\n");
			}
			else if (res == 0 && peer_ctx[idx].sfd == -1) {
				close(poll_fd[idx].fd);
				poll_fd[idx].fd = -1;
				poll_fd[idx].events = 0;
				poll_fd[idx].revents = 0;
				continue;
			} else 
				continue;

//			printf("revents %d, Client send: %s\n",
			       //poll_fd[idx].revents, peer_ctx[idx].buf);
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
		}
	}
	return;
}

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
	int i, value, linenum, nsrc;
	float fvalue;
	FILE *fd;
	char *line, *ptr;
	char *arg;
	ServerOpCodes opcode;

	nsrc = 0;
	linenum = 1;
	ptr = line = calloc(128, 1);
	
	fd = fopen(filename, "rw");
	if (fd == 0) {
		printf("fopen returned %s\n", strerror(errno));
		return FALSE;
	}

	printf("open socket\n");

	while (fgets(line, 127, fd) != NULL) {
		linenum++;
		if ((arg = strdelim(&line)) == NULL) {
			printf("arg %s\n", arg);
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
			printf("time param %d\n", value);
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
		case path_to_src:
			arg = strdelim(&line); 
			if (!arg || *arg == '\0')
				printf("%s line %d: missing integer value.",
				      filename, linenum);

			strncpy(options.path_to_src[nsrc], arg, MAX_LENGHT_NAME);
			nsrc++;
			break;
		case estimate:
			arg = strdelim(&line); 
			if (!arg || *arg == '\0')
				printf("%s line %d: missing integer value.",
				      filename, linenum);
			fvalue = atof(arg);
			printf("fvalue %f\n", fvalue);
			options.estimate[nsrc-1] = fvalue;
			break;
		case fthreshold:
			arg = strdelim(&line);
			if (!arg || *arg == '\0')
				printf("%s line %d: missing integer value.",
				      filename, linenum);
			fvalue = atof(arg);
			options.fthreshold[nsrc-1] = fvalue;
			break;
		case sthreshold:
			arg = strdelim(&line);
			if (!arg || *arg == '\0')
				printf("%s line %d: missing integer value.",
				      filename, linenum);
			fvalue = atof(arg);
			options.sthreshold[nsrc-1] = fvalue;
			break;
		default:
			printf("%s: line %d: mising handler for opcode %s\n",
			      filename, linenum, arg);
		}
		
//		printf("parse end\n");
		if ((arg = strdelim(&line)) != NULL && *arg != '\0')
			printf("%s line %d: garbage at end of line; \"%.200s\".",
			      filename, linenum, arg);
		line = ptr;
	}

	free(ptr);

	if(fclose(fd) != 0) {
		printf("error of fclose\n");
		exit(1);
	}
	printf("end parse\n");
	return TRUE;
}

int
accumulate_samples(int id) 
{
	int res, left, fifo_fd, fd, used;
	char buf[PACKET_SIZE];		//Our packet will have max size of 128
					//including id and special characters '\r\n'
	printf("src %s\n", options.path_to_src[id]);
	fd 	= open(options.path_to_src[id], O_RDONLY);
	fifo_fd = open(FIFO_PATH, O_NONBLOCK | O_WRONLY);
	
	printf("id %d pid %d: open fifo_fd %d, src_fd %d\n", id, getpid(), fifo_fd, fd);

	while (1) {
		used = sprintf(buf, "%d", id); 	/* The first two index for socket and fifo*/
		left = PACKET_SIZE - used - strlen("\r\n");

		res = read(fd, buf + used, left);
		if (res == -1) {
			if (errno == EINTR)
				continue;
			else {
				printf("read returned -1: %s\n", strerror(res));
				exit(1);
			}
		} else {
	//		left -= res;
			used += res;
		}
	
		sprintf(buf+used, "\r\n");
	
//		printf("accumulate buf %s\n"
//	      	       "id %d\n", buf, atoi(buf));

		res = write(fifo_fd, buf, PACKET_SIZE);
		if (res == -1) {
			printf("accumulate_samples(): write returned %d: %s\n", res, strerror(res));
			exit(1);
		}
	}

	close(fd);
	close(fifo_fd);

	return 0;
}

int 
accumulate_entropy(struct prng_context *prng)
{
	int fd, res, left, flag, id;
	float estimate;
	char *cp, *buf; // buf[PACKET_SIZE];

	buf = peer_ctx[1].buf;
	fd = poll_fd[1].fd;
	
	left = LINE_MAX;
	flag = 0;

	while (left) {
		res = read(fd, buf + flag, left);
		if (res == -1) {
			printf("accumulate entropy: read returned %d: %s\n", res, strerror(res));
			exit(1);
		}
		
		printf("recived entropy %d byts, %s\n", res, buf);

		flag += res;
		left -= res;
		
		id = buf[0]-48; /*ascii presentation of decimal*/
		estimate = atof(buf+2);

		printf("id %d, estimate %f\n", id, estimate);
		
		buf[flag] = '\0';
		memmove(buf, buf+8, strlen(buf)-8); /*Remove id and estimate*/
		cp = buf;
			
		while (*cp != '\0') {
			if (cp[0] == '\r' && cp[1] == '\n') {
				*cp = '\0';
				printf("accumulate entropy strlen buf %d\n", strlen(buf));
				feed_entropy(id, buf, strlen(buf), estimate, prng);
				printf("End \n");
				return 0;
			} else {
				cp++;
			}
		}
	}

	return 1;
}

static void 
sigterm_handler(int sig) 
{
	received_sigterm = sig;
}

void
init_peer(int fd, int i) 
{
	poll_fd[i].fd = fd;
	poll_fd[i].events = (POLLIN | POLLPRI);

	peer_ctx[i].sfd = fd;
	peer_ctx[i].bufused = 0;
}

struct entropy_pool fast_pool, slow_pool;
int add_to_fast[MAX_SOURCES];

int main(int argc, char **argv)
{
	int server_fd, fifo_fd, opt, res, i, nelems;
	size_t size;
	char req[256];
	char *path;
	struct prng_context prng;

	prng.used = 0;

	memset(add_to_fast, 0, MAX_SOURCES);
	set_program_name(argc, argv);
	
	printf("getopt start\n");
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
	printf("getopt end\n");
	
	argc -= optind;
	argv += optind;

	
	if (process_server_config(path) != 1)
		exit(1);

	printf("process_server_config end\n");
		
	res = entropy_pool_init(&fast_pool, options.nsources, options.entropy_hash);
	if (res == 0)
		printf("fast_pool.nsources %d\n"
		       "fast_pool.hdesc->name %s\n\n",
		       fast_pool.nsources, 
		       fast_pool.hdesc->name);
	
	res = entropy_pool_init(&slow_pool, options.nsources, options.entropy_hash);
	if (res == 0)
		printf("slow_pool.nsoursec %d\n"
		       "slow_pool.hdesc->name %s\n\n", 
		       slow_pool.nsources, 
		       slow_pool.hdesc->name);
	
	res = entropy_pool_set_k(&fast_pool, options.k);
	res = entropy_pool_set_k(&slow_pool, options.k);
	
	prng.gate_param = options.gate_param;
	
	res = prng_set_time_param(&prng, options.time_param);
	printf("prng_set_time_param %d", res);

	for (i = 0; i < options.nsources; i++) {
		res = entropy_pool_set_threshold(&fast_pool, i, options.fthreshold[i]);	
		if (res == 0)
	                printf("entropy_pool_set_threshold in fast %f\n", fast_pool.threshold[i]);

		res = entropy_pool_set_threshold(&slow_pool, i, options.sthreshold[i]);	
		if (res == 0)
			printf("entropy_pool_set_threshold in slow %f\n", slow_pool.threshold[i]);
	}

	if (prng_cipher_init(options.prng_cipher, &prng)) {
		printf("prng.cipher_name %s \n"
		       "prng.cipher_len %d \n"
		       "prng.cipher_key_size %d \n",
		       prng.cdesc->name,
		       prng.cdesc->block_size,
		       prng.cdesc->key_size);
	} else {
		printf("Error of prng_cipher_init\n");
		exit(1);
	}

	prng.cipher_ctx = prng.cdesc->context_new();

	if (prng_hash_init(options.prng_hash, &prng)) {
		printf("prng.hash_name %s\n"
		       "prng.digest_len %d\n",
		       prng.hdesc->name,
		       prng.hdesc->digest_len);
				
	} else {
		printf("Error of prng_hash_init\n");
		exit(1);
	}
	
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

	printf("open fifo %d\n", fifo_fd);
	
	for (i = 0; i < options.nsources; i++) {
		res = fork();
		switch (res) {
		case 0:
			sprintf(req, "%s %d %f", "./accumulate_samples", i, options.estimate[i]);
			res = system(req);
			if (res == -1) {
				printf("system returned -1: %s\n", strerror(res));
				exit(1);
			}
			break;
		case -1:
			printf("fork returned %d: %s\n", res, strerror(res));
			exit(1);
		default:
			break;
		}
	}
		
	server_fd = sock_unix_listen(DEFAULT_SOCK_PATH);
	if (server_fd == -1) {
		printf("Error of sock_unix_connect");
		exit(1);
	}
	
	sock_nonblock(server_fd);
	sock_nonblock(fifo_fd);
	printf("server_fd %d\n", server_fd);
	
	poll_fd = calloc(2, sizeof(struct pollfd));
	if (poll_fd == NULL) {
		perror("Calloc returned NULL.");
		exit(1);
	}

	peer_ctx = calloc(2, sizeof(struct peer));
	if (peer_ctx == NULL) {
		perror("Calloc returned NULL");
		exit(1);
	}
	
	init_peer(server_fd, 0);
	init_peer(fifo_fd, 1);

	nelems = 2;

	signal(SIGTERM, sigterm_handler);
	signal(SIGPIPE, SIG_IGN);

	for (;;) {
	//	printf("left %d\n", left);
		if (received_sigterm) {
			close(server_fd);
			close(fifo_fd);
			unlink(DEFAULT_SOCK_PATH);
			unlink(FIFO_PATH);
			exit(1);
		}

		res = poll(poll_fd, nelems, -1);
		if (res == -1 && errno != EINTR) {
			printf("poll returned %d: %s\n",
			      res, strerror(errno));
			break;
		}

		if (poll_fd[0].revents & POLLIN) {
			accept_connect(&nelems);
			poll_fd[0].revents = 0;

		} else if (poll_fd[1].revents & POLLIN) {
			if (accumulate_entropy(&prng)) 
				printf("Can not find id in packet\n");
			poll_fd[1].revents = 0;
			memset(peer_ctx[1].buf, 0, sizeof(peer_ctx[1].buf));
		} 
		
		if (prng.used < MIN_BUF_USED) {
			printf("prng.used %d\n\n\n\n", prng.used);
			size = STORAGE_SIZE - prng.used;
			prng_encrypt(&prng, prng.random_storage + prng.used, &size);
		}
 		
		process_events(nelems, &prng); 
	}	

	res = entropy_pool_deinit(&fast_pool);

	if (res == 0)
		printf ("fast_pool_hdesc %p,"
			"pool.nsources %d "
			"pool.k %d \n", 
			fast_pool.hdesc, 
			fast_pool.nsources, 
			fast_pool.k);

	return 0;
}
