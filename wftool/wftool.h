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



extern char *wf_argv[1024];
extern int wf_argc;


#endif

