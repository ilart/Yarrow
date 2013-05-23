#define DEFAULT_SOCK_PATH "/var/run/yarrow.socket"
#define PACKET_SIZE 128
#define FIFO_PATH "/tmp/fifo"
#define BASE 16
#define MAX_LENGHT_NAME	255

char get_arg(char **line);
int parce_attr(const char *path);
static void set_program_name();
static void print_used();

