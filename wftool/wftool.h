#ifndef WFTOOL_H_
#define WFTOOL_H_

#define WFT_DEBUG(fmt, ...)	printf("[%s %d] "fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__);

extern char print_name[32];
#define wfprintf(fmt, ...)	printf("[%s] "fmt, print_name, ##__VA_ARGS__);

#define dprintf(fmt, ...)	do { \
	if(wft_debug)	printf(fmt, ##__VA_ARGS__);\
} while (0)

extern int wft_debug;

extern int pipe_fd[2];
int init_pipe();
void close_pipe();

enum ARG_VALUE_TYPE{
	ARG_VALUE_TYPE_NONE,
	ARG_VALUE_TYPE_CHAR,
	ARG_VALUE_TYPE_INT,
	ARG_VALUE_TYPE_LONG,
	ARG_VALUE_TYPE_LONGLONG,
	ARG_VALUE_TYPE_STRING,
};
struct arg_parse_t
{
	char *key;
	void *value;
	int arg_idx;
	int has_arg;
	int (*arg_deal)(char *arg_key, char *arg_value, void *value);
	enum ARG_VALUE_TYPE value_type;
	long long int set_number;
	char *set_string;
};

extern char *wf_argv[1024];
extern int wf_argc;
int arg_parse(int argc, char **argv, struct arg_parse_t *arg_plist);
int arg_deal_default(char *arg_key, char *arg_value, void *value);

#endif

