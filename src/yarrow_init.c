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
	char prng_cipher[16];
	char prng_hash[16];
	char entropy_hash[16];
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
	int i, value, linenum;
	FILE *fd;
	char *line, *ptr;
	char *arg;
	ServerOpCodes opcode;

	linenum = 1;
	ptr = line = calloc(128, 1);
	
	fd = fopen(filename, "rw");
	if (fd == 0)
		return FALSE;

	while (fgets(line, 127, fd) != NULL) {
		linenum++;

		if ((arg = strdelim(&line)) == NULL) {
		//	printf("arg %s\n", arg);
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
		
//		printf("arg %s name %s", arg, attr_table[i].name);
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
		default:
			printf("%s: line %d: mising handler for opcode %s\n", filename, linenum, arg);
		}
	
		if ((arg = strdelim(&line)) != NULL && *arg != '\0')
			printf("%s line %d: garbage at end of line; \"%.200s\".",
			       filename, linenum, arg);
		line = ptr;
	}

	free(ptr);

	if(fclose(fd) != 0) {
//		printf("error of fclose\n");
		exit(1);
	}
	return TRUE;
}

int
parse_request(const char *buf)
{	
	int len;

	len = strlen(buf);	
	if (strspn(buf, "\n")) {
		return 1;
	}
	return 0;
}

void *
read_fd(int fd, char *buf) 
{
	int res, end, left;
	char *tmp;
	end = 0;
	res = 0;
	left = LINE_MAX;
	tmp = buf;

	while (!end) { 
		res = read(fd, buf, left);
		printf("read %d byts: %s\n", res, buf);
		if (res == -1)
			perror("Error of read");

		end = parse_request(buf);
		left -= res;
		buf += res;
	}
	
	buf = tmp;

	printf("Read str: %s, strlen %d from fd %d \n", buf, (int) strlen(buf),  fd);
	return buf;
}

void
write_fd(int fd, char *buf)
{
	int res;

	res = write(fd, buf, LINE_MAX);
	if (res == -1)
		perror("Error of write");
		
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

	printf("xrealloc: old ptr %p new ptr %p sizeof new %d\n", mem, ptr, (int) sizeof(ptr));
	return ptr;
}

void 
process_events(struct pollfd *ufds, int count) 
{
	int i;
	char request_buf[LINE_MAX];

//	printf("count of desc %d\n", count);
	for(i = 0; i < count; i++) {
		
		if (ufds[i].revents & POLLHUP) {
			ufds[i].fd = -1;
			ufds[i].events = 0;
			continue;

		} else	if (ufds[i].revents & (POLLIN|POLLPRI)) {
			read_fd(ufds[i].fd, request_buf);
			printf("revents %d, Client send: %s\n", ufds[i].revents, request_buf);
			//res = parse_request(request_buf);
			//
			//now, server echo.
			write_fd(ufds[i].fd, request_buf);
		}
		if (ufds[i].revents & (POLLERR|POLLNVAL)) {
			printf("we recived %d event from %d desc\n", ufds[i].revents, ufds[i].fd);
			ufds[i].fd = -1;
			ufds[i].events = 0;
			ufds[i].revents = 0;
		}

//		printf("ufds %d event %d revent %d\n", ufds[i].fd, ufds[i].events, ufds[i].revents);

		ufds[i].revents = 0;
	}

}

int 
find_unused_fd(struct pollfd *poll_fd, int *count)
{
	int i, size;

	for(i = 0; i < count[0]; i++) {
		if (poll_fd[i].fd == -1 && poll_fd[i].events == 0)
			return i;
	}

	size = count[0] * sizeof(struct pollfd);
	poll_fd = xrealloc0(poll_fd, size, size + sizeof(struct pollfd));	
	count[0] += 1;
	return count[0]-1;
}



struct entropy_pool fast_pool, slow_pool;
int add_to_fast[MAXSOURCES];

int main(int argc, char **argv)
{
	int server_fd, client_fd, opt, res, i, fd;
	size_t size = 512;
	int buf_random[512];
	char *path;
	double treshd;
	unsigned char *tmp_s;
	struct prng_context prng;
	struct pollfd *events;
	struct sockaddr saddr;
	socklen_t slen;

	memset(add_to_fast, 0, sizeof(add_to_fast));
	set_program_name(argc, argv);
	
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
	
	argc -= optind;
	argv += optind;

	
	if (process_server_config(path) != 1)
		exit(1);
		
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

	slen = sizeof(saddr);

	events = calloc(1, sizeof(struct pollfd));
	if (events == NULL) {
		perror("error of calloc");
		exit(1);
	}

	nelems = 1;
	events[0].fd = server_fd;
	events[0].events = (POLLIN|POLLPRI);

	terminated = 0;
	i = 0;
	client_fd = 12;

	while (!terminated) {
		res = poll(events, nelems, -1);
		if (res >= 0) {
			client_fd = accept(server_fd, &saddr, &slen);
			if (client_fd > 0) {
				idx = find_unused_fd(events, &nelems);
				events[idx].fd = client_fd;
				events[idx].events = (POLLIN|POLLPRI|POLLHUP|POLLERR);
			
				printf("we recive connect fd=%d nelems %d sizeof events %d sizeof events[1] %d \n", client_fd, nelems, (int ) sizeof(events), (int) sizeof(events[1]));

				sock_nonblock(client_fd);
				client_fd = 0;
				if (res == 1)
					continue;
			} else if (client_fd == -1 && errno != EAGAIN) {
				printf("error of accept");
				exit(1);
			}
			
			process_events(events, nelems); 
//			printf("iter \n");
		}
		else {
			perror("error of poll or timeout");
			exit(1);	
		}
	}	
	
	close(server_fd);
	close(client_fd);
	unlink("/var/run/yarrow.socket");

	

	close(fd);
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
