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
#define get_opposite(num)	(~num + 1)		// 取num 的相反数
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




extern int wf_kill_exe(int pid, char *name);
extern int wf_get_selfexe_path(char *path, int len);

extern long wf_getsys_uptime(unsigned long *up_time);
#ifndef get_system_uptime
#define get_system_uptime(up_time)	wf_getsys_uptime(up_time)
#endif




extern int close_fd_self();
#define close_fd_parent()	close_fd_self()

extern int waitpid_time(pid_t pid, int *pstatus, unsigned int max_time);
extern int create_child_process(const char *filename, char *const argv[], int close_std);

#include <signal.h>
extern void wf_registe_exit_signal(__sighandler_t exit_call);
// void (*exit_call)(void)
extern void wf_demon(__sighandler_t exit_call);
extern void wf_daemon_action(int nochdir, int noclose, __sighandler_t exit_call);





extern int getSysCmd_output(char *cmd,char *output, unsigned int size);
extern int exe_exist_check(char *name);
extern void wf_check_exit(int semkey, char *name);


extern char *wf_std_error(int *errcode);


// -------------------------------------------------------------------
#ifndef WF_CURSOR
#define WF_CURSOR
#define save_cursor()			printf("\033[s")		// 保存光标位置
#define hide_cursor()			printf("\033[?25l")		// 隐藏光标
#define recover_cursor()		printf("\033[u")		// 恢复光标位置
#define show_cursor()		printf("\33[?25h")		// 显示光标
#define default_cursor()		printf("\033[0m\n")		// 关闭所有属性
#define setBlueWhite()		printf("\033[44;37m")	// 设置蓝底白字
#endif
// -------------------------------------------------------------------

#endif

