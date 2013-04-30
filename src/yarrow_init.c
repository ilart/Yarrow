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
	path,
	estimate,
	lenght_entropy
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
	{"path_to_src", path},
	{"estimate", estimate},
	{"lenght_entropy", lenght_entropy}
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
	int estimate[MAX_SOURCES];
	int lenght_entropy[MAX_SOURCES];
}	Options;


Options options;


struct peer {
	int sfd;
	char buf[LINE_MAX+1];
	int bufused;
} *peer_ctx;

struct pollfd *poll_fd;

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
	FILE *fd;
	char *line, *ptr;
	char *arg;
	ServerOpCodes opcode;

	nsrc = 0;
	linenum = 1;
	ptr = line = calloc(128, 1);
	
	fd = fopen(filename, "rw");
	if (fd == 0)
		return FALSE;
	
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
		
		printf("arg %s name %s\n", arg, attr_table[i].name);
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
		case path:
			nsrc++;
			arg = strdelim(&line); 
			if (!arg || *arg == '\0')
				printf("%s line %d: missing integer value.",
				      filename, linenum);

			strncpy(options.path_to_src[nsrc], arg, MAX_LENGHT_NAME);
			break;
		case estimate:
			arg = strdelim(&line); 
			if (!arg || *arg == '\0')
				printf("%s line %d: missing integer value.",
				      filename, linenum);
			value = atoi(arg);
			options.estimate[nsrc-1] = value;
			break;
		case lenght_entropy:
			arg = strdelim(&line); 
			if (!arg || *arg == '\0')
				printf("%s line %d: missing integer value.",
				      filename, linenum);
			value = atoi(arg);
			options.lenght_entropy[nsrc-1] = value;
			break;
		default:
			printf("%s: line %d: mising handler for opcode %s\n",
			      filename, linenum, arg);
		}
		
		printf("parse end\n");
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
	return TRUE;
}

struct entropy_pool fast_pool, slow_pool;
int add_to_fast[MAX_SOURCES];

int main(int argc, char **argv)
{
	int server_fd, opt, res, i, fd, nelems;
	char *path;
	struct prng_context prng;

	memset(add_to_fast, 0, sizeof(add_to_fast));
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
		printf("pool.nsources %d\n"
		       "pool.k %d\n"
		       "pool.hdesc->name %s\n\n",
		       fast_pool.nsources, 
		       fast_pool.k, 
		       fast_pool.hdesc->name);

	res = entropy_pool_set_k(&fast_pool, options.k);
	
	res = entropy_pool_init(&slow_pool, options.nsources, options.entropy_hash);
	if (res == 0)
		printf("slow_pool.nsoursec %d\n"
		       "slow_pool.k %d\n" 
		       "slow_pool.hdesc->name %s\n\n", 
		       slow_pool.nsources, 
		       slow_pool.k, 
		       slow_pool.hdesc->name);

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
	
	res = entropy_pool_set_nsources(&fast_pool, 15);
	if (res == 0)
	        printf("entropy_pool_set_nsources %d \n", fast_pool.nsources);

	res = entropy_pool_get_nsources(&fast_pool);
	if (res != 0)
                printf("entropy_pool_get_nsources %d\n", res);
	
	server_fd = sock_unix_listen(DEFAULT_SOCK_PATH);
	if (server_fd == -1) {
		printf("Error of sock_unix_connect");
		exit(1);
	}

	sock_nonblock(server_fd);
	printf("server_fd %d\n", server_fd);

	poll_fd = calloc(1, sizeof(struct pollfd));
	if (poll_fd == NULL) {
		perror("error of calloc");
		exit(1);
	}

	poll_fd[0].fd = server_fd;
	poll_fd[0].events = (POLLIN|POLLPRI);

	peer_ctx = calloc(1, sizeof(struct peer));
	if (peer_ctx == NULL) {
		perror("Calloc returned NULL");
		exit(1);
	}
	
	peer_ctx[0].sfd = server_fd;
	peer_ctx[0].bufused = 0;
	nelems = 1;

	i = 0;
	
	while (1) {
		res = poll(poll_fd, nelems, -1);
		//printf("poll %d %d\n", res, poll_fd[0].revents);
		if (res > 0) {
			if (poll_fd[0].revents & POLLIN) {
				accept_connect(&nelems);
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

/*
	res = entropy_pool_set_k(&fast_pool, 1);
	if (res == 0)
		printf("entropy_pool_set_k %d\n", fast_pool.k);

	res = entropy_pool_get_k(&fast_pool);
	if (res != 0)
                printf("entropy_pool_get_k %d\n", res);
	printf("\n");

	res = entropy_pool_set_threshold(&fast_pool, 0, 120.0);	
	if (res == 0)
                printf("entropy_pool_set_threshold in fast %f\n", fast_pool.threshold[0]);

	res = entropy_pool_set_threshold(&slow_pool, 0, 181.0);	
	if (res == 0)
                printf("entropy_pool_set_threshold in slow %f\n", slow_pool.threshold[0]);
	
	treshd = entropy_pool_get_threshold(&fast_pool, 0);	
	if (treshd != 0)
                printf("entropy_pool_get_threshold %f\n", treshd);
	printf("\n");
	
	fd = open("/dev/urandom" , O_RDONLY);
	if (fd == -1)
		perror("Error of open");

	res = read(fd, &prng.key, sizeof(prng.key));
	if (res == -1)
		perror("Error of write");

	printf("key before reseed \n");
	for (i = 0; i < ARRAY_SIZE(prng.key); i++) {
		printf("%u ", prng.key[i]);
	}
	
	printf("\n");

	res = read(fd, buf, sizeof(buf));
	if (res < 0) {
		perror("error of read");		
	}

	prng.gate_param = 10;

	res = prng_set_time_param(&prng, 10);
	printf("prng_set_time_param %d", res);

	res = prng_get_time_param(&prng);
	printf("prng_set_time_param %d", res);

	feed_entropy(0, buf, 16, 0.5, &prng);
	feed_entropy(0, buf+16, 16, 0.5, &prng);
	feed_entropy(0, buf+32, 16, 0.5, &prng);
	feed_entropy(0, buf+48, 16, 0.5, &prng);
		

	res = entropy_pool_add(&fast_pool, 0, buf, 33, 0.5);
	if (res == 0)
		printf("pool.estimate add %f \n", 
			fast_pool.estimate[0]);
	else {
		printf("error of entropy_pool_add");
		return EPOOL_FAIL;
	}
	printf("\n");
	

	res = entropy_pool_get_nsources(&fast_pool);

//	prng_reseed(&prng, &fast_pool, 10);

	printf("\n key after reseed \n");
	for (i = 0; i < ARRAY_SIZE(prng.key); i++) {
		printf("%u ", prng.key[i]);
	}
	
	printf("\n counter after reseed \n");
	for (i = 0; i < ARRAY_SIZE(prng.counter); i++) {
		printf("%u ", prng.counter[i]);
	}

	prng_encrypt(&prng, buf_random, &size);	
	printf("\nrandom values\n");
	for (i = 0; i < 512/4; i++) {
		printf(" %d, ", buf_random[i]);
	}

	res = entropy_pool_is_thresholded(&fast_pool);
	printf("thresholded = %d \n", res);

	printf("\ndigest_len %d\n", fast_pool.hdesc->digest_len);	
	
	tmp_s = entropy_pool_bytes(&slow_pool);
	printf("slow_pool_byts %s \n", tmp_s);

	entropy_pool_clean(&fast_pool);
	printf("entropy_pool_clean %s", fast_pool.buffer);


//	slow_pool.hdesc->finalize(&slow_pool, (void *)tmp_buf);
//	printf("hash = %s \n", tmp_buf);
	
*/	res = entropy_pool_deinit(&fast_pool);

	if (res == 0)
		printf ("fast_pool_hdesc %p,"
			"pool.nsources %d "
			"pool.k %d \n", 
			fast_pool.hdesc, 
			fast_pool.nsources, 
			fast_pool.k);


	close(fd);


return 0;
}
