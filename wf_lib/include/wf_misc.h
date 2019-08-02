#ifndef WF_MISC_H_
#define WF_MISC_H_

#ifndef ARRAY_NUM
#define ARRAY_NUM(arg)	sizeof(arg)/sizeof(arg[0])
#endif

#ifndef WF_PVAR
#define WF_PVAR(var, fmt)		printf(#var" = "fmt" \n", var)
#define WF_PVAR_INT(var)		WF_PVAR(var, "%d")
#define WF_PVAR_STR(var)		WF_PVAR(var, "%s")
#endif

#ifndef WF_ASSERT
#define WF_ASSERT(exp)	if(!(exp)){fprintf(stderr, "ASSERT "#exp" ERROR:%s:%d \n", __FUNCTION__, __LINE__); exit(-1);}
#endif

#ifndef wf_free
#define wf_free(ptr) do { \
	free(ptr); \
	ptr = NULL; \
} while(0)
#endif


#ifndef exit_error
#define exit_error(str)	do { \
	printf("%s\n", str); \
	printf("exit: %s [%d] \n", __FILE__, __LINE__); \
	exit(0); \
} while (0)
#endif







#ifndef get_opposite
#define get_opposite(num)	(~num + 1)		// ȡnum ���෴��
#endif

#ifndef get_integer
#define get_integer(num, n)	(((num+n-1)/n)*n)
#endif

#define srand_curtime()		srand((unsigned short)time(NULL))
#define rand_interval(a, b)	(a+((double)((b-a)*rand())/(double)(RAND_MAX)))
#define rand_natural(max)	(rand() % max)

#ifndef	M_PI
#define	M_PI		3.14159265358979323846	/* pi */
#endif
extern double radian(double angle);
extern double angle(double radian);





#include <unistd.h>
extern pid_t record_lock_test(int fd, int type, off_t offset, int whence, off_t len);

#define record_lock_rtest(fd, offset, whence, len) \
	record_lock_test((fd), F_RDLCK, (offset), (whence), (len))
#define record_lock_wtest(fd, offset, whence, len) \
	record_lock_test((fd), F_WRLCK, (offset), (whence), (len))

#include <fcntl.h>
extern int record_lock(int fd, int cmd, int type, off_t offset, int whence, off_t len);

#define record_lock_read(fd, offset, whence, len) \
	record_lock((fd), F_SETLK, F_RDLCK, (offset), (whence), (len))
#define record_lock_readw(fd, offset, whence, len) \
	record_lock((fd), F_SETLKW, F_RDLCK, (offset), (whence), (len))
#define record_lock_write(fd, offset, whence, len) \
	record_lock((fd), F_SETLK, F_WRLCK, (offset), (whence), (len))
#define record_lock_writew(fd, offset, whence, len) \
	record_lock((fd), F_SETLKW, F_WRLCK, (offset), (whence), (len))
#define record_unlock(fd, offset, whence, len) \
	record_lock((fd), F_SETLK, F_UNLCK, (offset), (whence), (len))



#include <time.h>
struct wf_time_period
{
	unsigned char week_flags;	// 0x01:sunday; 0x02:monday; ...; 0x40:saturday; 0x7F:all day
	unsigned char start_hour;
	unsigned char start_min;
	unsigned char end_hour;
	unsigned char end_min;
};
extern int wf_time_period_is_overlap(struct wf_time_period *time_new, struct wf_time_period *time_old);
extern int wf_time_period_check(struct wf_time_period *time_period);
extern int wf_time_period_cmp(struct tm *time, struct wf_time_period *time_period);




//#define is_exist_file(file)		access(file, F_OK)





extern void bubble_sort_char(char *str, int start_index, int end_index);
extern void bubble_sort_int(int *num, int start_index, int end_index);
extern void randsort(long begin, long end, long *out, unsigned int out_size);




extern void alarm_start(unsigned int seconds, void (*func)(int));
extern void alarm_again(unsigned int seconds);
extern void alarm_cancel();

extern int run_with_timeout (int timeout, void (*fun) (void *), void *arg);



extern int wf_kill_exe(int pid, char *name);
extern int wf_get_selfexe_path(char *path, int len);

extern long wf_getsys_uptime(unsigned long *up_time);
#ifndef get_system_uptime
#define get_system_uptime(up_time)	wf_getsys_uptime(up_time)
#endif




extern int close_fd_self();
#define close_fd_parent()	close_fd_self()

extern int waitpid_sec(pid_t pid, int *pstatus, unsigned int timecnt);
extern int waitpid_100usec(pid_t pid, int *pstatus, unsigned int timecnt);
extern int create_child_process(const char *exename, char *const argv[], int close_std, int *pipefd);
extern int create_child_wait_sec(const char *exename, char *const argv[], int close_std, int *pipefd, unsigned int timecnt);
extern int create_child_wait_100usec(const char *exename, char *const argv[], int close_std, int *pipefd, unsigned int timecnt);

extern int pipe_init(int *pipefd);
extern void pipe_close(int *pipefd);


#include <signal.h>
extern void wf_registe_exit_signal(__sighandler_t exit_call);
// void (*exit_call)(void)
extern void wf_demon(__sighandler_t exit_call);
extern void wf_daemon_action(int nochdir, int noclose, __sighandler_t exit_call);





extern int getSysCmd_output(char *cmd,char *output, unsigned int size);
extern int exe_exist_check(char *name);
extern void wf_check_exit(int semkey, char *name);
extern int already_running(const char *filename);


extern char *wf_std_error(int *errcode);

extern void __fprint_strn(FILE *fp, char *str, unsigned int max_num, char *startl, char *endl);
extern void fprint_strn(FILE *fp, char *str, unsigned int max_num);
#define print_strn(str, max_num) __fprint_strn(stdout, str, max_num, NULL, "\n")

extern void fprint_bytes(FILE *fp, unsigned char *byte, unsigned int max_num);
#define print_bytes(byte, max_num) fprint_bytes(stdout, byte, max_num)


struct child_cmd_t
{
	char cmd[16];
	int (*init_call)(int argc, char **argv, struct child_cmd_t *pcmd);
	void (*usage_call)(void);
	int (*cmd_call)(int argc, char **argv);
};
extern int wf_child_cmd(int argc, char **argv, struct child_cmd_t *cmd_list, int cmd_size, char *main_cmd_name, void (*whole_usage)());
#define wf_child_cmd_simple(argc, argv, cmd_array, main_cmd_name) wf_child_cmd(argc, argv, cmd_array, ARRAY_NUM(cmd_array), main_cmd_name, NULL)
#define wf_child_cmd_mini(cmd_array, main_cmd_name) wf_child_cmd(argc, argv, cmd_array, ARRAY_NUM(cmd_array), main_cmd_name, NULL)


enum ARG_VALUE_TYPE{
	ARG_VALUE_TYPE_NONE,
	ARG_VALUE_TYPE_CHAR,
	ARG_VALUE_TYPE_INT,
	ARG_VALUE_TYPE_LONG,
	ARG_VALUE_TYPE_LONGLONG,
	ARG_VALUE_TYPE_UINT,
	ARG_VALUE_TYPE_ULONG,
	ARG_VALUE_TYPE_ULONGLONG,
	ARG_VALUE_TYPE_STRING,
	ARG_VALUE_TYPE_OTHER
};
struct arg_parse_t
{
	char *key;
	void *value;
	int arg_idx;
	int has_arg;
	int (*arg_deal)(char *arg_key, char *arg_value, int value_type, void *value);
	enum ARG_VALUE_TYPE value_type;
	long long int set_number;
	char *set_string;
};
#define arg_parse_t_init_null {NULL, NULL, 0, 0, NULL, 0, 0, NULL},

struct arg_parse_hook_data{
	int argc;
	char **argv;
//	int *new_argc;
//	char **new_argv;
	struct arg_parse_t *arg_plist;
	struct arg_parse_t *last_match;
};

struct arg_parse_hook{
	int (*not_match_key)(char *arg, struct arg_parse_hook_data *hook_data, void *extend); // retrun ture: skip this arg; return false: store to new_argv
	void *not_match_key_hook_extend;
};

extern int arg_deal_default(char *arg_key, char *arg_value, int value_type, void *value);
extern int arg_parse_go(int argc, char **argv, struct arg_parse_t *arg_plist, int *new_argc, char **new_argv, struct arg_parse_hook *hook);
#define arg_parse(argc, argv, arg_plist, new_argc, new_argv) arg_parse_go(argc, argv, arg_plist, new_argc, new_argv, NULL)



// -------------------------------------------------------------------
#ifndef WF_CURSOR
#define WF_CURSOR
#define save_cursor()			printf("\033[s")		// ������λ��
#define hide_cursor()			printf("\033[?25l")		// ���ع��
#define recover_cursor()		printf("\033[u")		// �ָ����λ��
#define show_cursor()		printf("\33[?25h")		// ��ʾ���
#define default_cursor()		printf("\033[0m\n")		// �ر���������
#define setBlueWhite()		printf("\033[44;37m")	// �������װ���
#endif
// -------------------------------------------------------------------

#endif

