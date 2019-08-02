#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/sysinfo.h>
#include <signal.h>
#include <setjmp.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/types.h>
#include <sys/sem.h>
#include <dirent.h>
#include <limits.h>
#include <sys/param.h>
#include <sys/stat.h>		// umask
#include <sys/resource.h>	// getrlimit
#include <fcntl.h>
#if 0
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>		// sched_setaffinity
#endif
#include "wf_misc.h"



#if 0
void abort()			// POSIX-style abort() function
{
	sigset_t mask;
	struct sigaction action;

	// caller can't ignore SIGABRT, if so reset to default
	sigaction(SIGABRT, NULL, &action);
	if(action.sa_handler == SIG_IGN){
		action.sa_handler = SIG_DFL;
		sigaction(SIGABRT, &action, NULL);
	}
	if(action.sa_handler == SIG_DFL)
		fflush(NULL);				// flush all open stdio streams

	// caller can't block SIGABRT; make sure it's unblocked.
	sigfillset(&mask);
	sigdelset(&mask, SIGABRT);
	sigprocmask(SIG_SETMASK, &mask, NULL);

	kill(getpid(), SIGABRT);

	// if we're here, process caught SIGABRT and returned.
	fflush(NULL);				// flush all open stdio streams
	action.sa_handler = SIG_DFL;
	sigaction(SIGABRT, &action, NULL); // reset to default

	sigprocmask(SIG_SETMASK, &mask, NULL);
	kill(getpid(), SIGABRT);
	exit(1);
}
#endif
#if 0
// need CAP_SYS_NICE (need root)
int bind_cpu()
{
	cpu_set_t set;
	int ret, cur_cpu_num = 0;
	unsigned long i, cpu = __CPU_SETSIZE;

	CPU_ZERO(&set);
	ret = sched_getaffinity(0, sizeof(cpu_set_t), &set);
	if(ret < 0)
		return ret;
	for(i=0; i<__CPU_SETSIZE; i++){
		if(CPU_ISSET(i, &set)){
			if(cpu == __CPU_SETSIZE)
				cpu = i;
			++cur_cpu_num;
		}
		if(cur_cpu_num > 1)
			break;
	}

	if(cur_cpu_num <= 1)
		return 0;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);

	return sched_setaffinity(0, sizeof(cpu_set_t), &set);
}
#endif










double radian(double angle)
{
	return ((M_PI/180.0) * angle);
}
double angle(double radian)
{
	return ((180.0/M_PI) * radian);
}


pid_t record_lock_test(int fd, int type, off_t offset, int whence, off_t len)
{
	struct flock lock;

	lock.l_type = type;	// F_RDLCK,  F_WRLCK
	lock.l_start = offset;
	lock.l_whence = whence;	// SEEK_SET,  SEEK_CUR, SEEK_END
	lock.l_len = len;

	if( fcntl(fd, F_GETLK, &lock) < 0 )
		return (pid_t)0;
	if(lock.l_type == F_UNLCK)
		return (pid_t)0;

	return lock.l_pid;
}

int record_lock(int fd, int cmd, int type, off_t offset, int whence, off_t len)
{
	struct flock lock;

	lock.l_type = type;	// F_RDLCK,  F_WRLCK,  F_UNLCK
	lock.l_start = offset;
	lock.l_whence = whence;	// SEEK_SET,  SEEK_CUR, SEEK_END
	lock.l_len = len;

	return fcntl(fd, cmd, &lock);
}


static unsigned char wf_week_flags_tomorrow(unsigned char day_flags)
{
	unsigned char tomorrow_flags = 0;

	if(!day_flags)
		return tomorrow_flags;

	tomorrow_flags = day_flags << 1;
	if(tomorrow_flags & 0x80){
		tomorrow_flags = tomorrow_flags | 0x01;
		tomorrow_flags = tomorrow_flags & 0x7F;
	}
	return tomorrow_flags;
}

int wf_time_period_is_overlap(struct wf_time_period *time_new, struct wf_time_period *time_old)
{
	int new_start, new_end, old_start, old_end;
	//int hour_24 = 1440;	// 24 * 60;
	unsigned char tomorrow_flags;

	if(!time_new || !time_old)
		return 0;
	if(!time_new->week_flags || !time_new->week_flags)
		return 0;

	new_start = time_new->start_hour * 60 + time_new->start_min;
	new_end = time_new->end_hour * 60 + time_new->end_min;
	old_start = time_old->start_hour * 60 + time_old->start_min;
	old_end = time_old->end_hour * 60 + time_old->end_min;
	
	if(new_start <= new_end && old_start <= old_end){
		if(time_new->week_flags & time_old->week_flags){
			if(new_start <= old_end && new_end >= old_start)
				return 1;
		}
	}

	if(new_start > new_end){
		tomorrow_flags = wf_week_flags_tomorrow(time_new->week_flags);
		if(time_new->week_flags & time_old->week_flags){
			//printf("---new_start > new_end----today---\n");
			if(new_start <= old_end)
				return 1;
			if(old_start > old_end)
				return 1;
		}
		if(tomorrow_flags & time_old->week_flags){
			//printf("---new_start > new_end----tomorrow---\n");
			if(new_end >= old_start)
				return 1;
		}
	}

	if(old_start > old_end){
		tomorrow_flags = wf_week_flags_tomorrow(time_old->week_flags);
		if(time_new->week_flags & time_old->week_flags){
			//printf("---old_start > old_end----today---\n");
			if(new_end >= old_start)
				return 1;
			if(new_start > new_end)
				return 1;
		}
		if(tomorrow_flags & time_new->week_flags){
			//printf("---old_start > old_end----tomorrow---\n");
			if(new_start <= old_end)
				return 1;
		}
	}
	
	return 0;
}

int wf_time_period_check(struct wf_time_period *time_period)
{
	if(!time_period->week_flags)
		return 0;
	if(time_period->start_hour > 23 || time_period->end_hour > 23)
		return 0;
	if(time_period->start_min > 59 || time_period->end_min > 59)
		return 0;

	return 1;
}

int wf_time_period_cmp(struct tm *time, struct wf_time_period *time_period)
{
	int tm_day = time->tm_wday;
	int yesterday = 0;
	int start;
	int end;
	int now;

	if (tm_day < 0 || tm_day > 6)
		return 0;
	if (time_period->week_flags == 0)
		return 1;

	if (tm_day == 0)
		yesterday = 6;
	else 
		yesterday = tm_day - 1;

	if ((time_period->week_flags & (0x1 << tm_day | 0x1 << yesterday)) == 0) 
		return 0;

	start = time_period->start_hour * 60 + time_period->start_min;
	end  = time_period->end_hour * 60 + time_period->end_min;
	now = time->tm_hour * 60 + time->tm_min;

	/*  nomal time : like 8:00-12:00 */
	if (end >= start)
		goto compare;

	/* start < end. accoss day. like 22:00-3:00*/
	if (time_period->week_flags & 1 << yesterday) {
		if (now <= end)
			return 1;
	}

	if (time_period->week_flags & 1 << tm_day) 
		end = 24 * 60;
compare:
	if (!(time_period->week_flags & 1 << tm_day))
		return 0;
	if (now >= start && now <= end)
		return 1;
	return 0;
}


void bubble_sort_char(char *str, int start_index, int end_index)
{
	int i, j;
	char k;
	
	for(i=start_index+1; i<end_index; i++)
	{
		for(j=start_index; j<end_index+1+start_index-i; j++)
		{
			if(str[j] > str[j+1])
			{
				k = str[j];
				str[j] = str[j+1];
				str[j+1] = k;
			}
		}
	}
}
void bubble_sort_int(int *num, int start_index, int end_index)
{
	int i, j;
	int k;
	
	for(i=start_index+1; i<end_index; i++)
	{
		for(j=start_index; j<end_index+1+start_index-i; j++)
		{
			if(num[j] > num[j+1])
			{
				k = num[j];
				num[j] = num[j+1];
				num[j+1] = k;
			}
		}
	}
}

void randsort(long begin, long end, long *out, unsigned int out_size)
{
	long count = end - begin;
	long i, tmp, idx;

	if((count <= 0) || (out_size <= count))	// out_size >= count +1
		return;
	for(i=0; i<=count; i++)
		out[i] = begin + i;
	srand_curtime();
	for(i=0; i<=count; i++){
		idx = rand_natural(count);
		tmp = out[idx];
		out[idx] = out[i];
		out[i] = tmp;
	}
}


void alarm_start(unsigned int seconds, void (*func)(int))
{
	signal(SIGALRM, func);
	alarm(seconds);
}

void alarm_again(unsigned int seconds)
{
	alarm(seconds);
}

void alarm_cancel()
{
	alarm(0);
}


/*
��غ�����longjmp, siglongjmp, setjmp
��ͷ�ļ���#include <setjmp.h>
�������壺int sigsetjmp(sigjmp_buf env, int savesigs)
����˵����sigsetjmp()�ᱣ��Ŀǰ��ջ������Ȼ��Ŀǰ�ĵ�ַ��һ���Ǻţ�
���ڳ��������ط�����siglongjmp()ʱ���ֱ����������Ǻ�λ�ã�Ȼ��ԭ��ջ�����������ִ�С�
����envΪ��������Ŀǰ��ջ������һ������Ϊȫ�ֱ���
����savesigs��Ϊ��0�������õ��źż���Ҳ��һ�鱣��
��sigsetjmp()����0ʱ�����Ѿ����üǺ��ϣ������ط�0�������siglongjmp������ת������
���أ���ֱ�ӵ�����Ϊ0������siglongjmp���÷�����Ϊ��0

Ӧ��: �������alarm����ʵ�ֺ�����ʱ����
*/
static sigjmp_buf run_with_timeout_env;
static volatile sig_atomic_t canjump = 0;
static void abort_run_with_timeout(int sig)
{
	if(canjump == 0) // ��sigjmp_buf ��sigsetjmp��ʼ�����֮ǰ����ֹ����siglongjmp
		return;
	
	if(sig == SIGALRM){
		siglongjmp(run_with_timeout_env, 1);
		canjump = 0;
	}
}
int run_with_timeout (int timeout, void (*fun) (void *), void *arg)
{
	if (timeout == 0)
	{
		fun(arg);
		return 0;
	}

	signal(SIGALRM, abort_run_with_timeout);
	if (sigsetjmp(run_with_timeout_env, 1) != 0)
	{
		/* Longjumped out of FUN with a timeout. */
		signal (SIGALRM, SIG_DFL);
		return 1;
	}
	
	canjump = 1;
	alarm(timeout);
	fun(arg);

	alarm(0);
	signal(SIGALRM, SIG_DFL);
	return 0;
}


int wf_kill_exe(int pid, char *name)
{
	char cmd_buf[128]={'\0'};
	if(pid > 0)
		sprintf(cmd_buf, "kill -9 %d", pid);
	else if(name)
		sprintf(cmd_buf, "kill -9 `pidof %s`", name);
	else
		return -1;
	return system(cmd_buf);
}

int wf_get_selfexe_path(char *path, int len)
{
	char buf[256] = {0, };
	int ret = readlink("/proc/self/exe", buf, sizeof(buf) - 1);

	if (ret < 0)
		return ret;
	if (ret > len - 1)
		ret = len - 1;
	strncpy(path, buf, ret);
	path[ret + 1] = 0;
	return ret;
}

long wf_getsys_uptime(unsigned long *up_time)
{
/*
struct sysinfo
{
	long uptime;			// Seconds since boot 
	unsigned long loads[3];		// 1, 5, and 15 minute load averages 
	unsigned long totalram;		// Total usable main memory size 
	unsigned long freeram;		// Available memory size 
	unsigned long sharedram;	// Amount of shared memory 
	unsigned long bufferram;	// Memory used by buffers 
	unsigned long totalswap;	// Total swap space size 
	unsigned long freeswap;		// swap space still available 
	unsigned short procs;		// Number of current processes 
	unsigned short pad;		// explicit padding for m68k 
	unsigned long totalhigh;	// Total high memory size 
	unsigned long freehigh;		// Available high memory size 
	unsigned int mem_unit;		// Memory unit size in bytes 
	char _f[20-2*sizeof(long)-sizeof(int)];	// Padding: libc5 uses this.. 
};
*/
	struct sysinfo info;
	memset(&info, 0, sizeof(info));
	sysinfo(&info);
	if(up_time)
		*up_time = info.uptime;

	return info.uptime;
}


void close_all_fd(int close_std)
{
#ifdef OPEN_MAX
	long open_max = OPEN_MAX;
#else
	long open_max = 0;
#endif
	int i = 0;

	if(open_max == 0)
	{
	#ifdef NOFILE		// <sys/param.h>
		open_max = NOFILE;
	#else
		errno = 0;
		open_max = sysconf(_SC_OPEN_MAX);
		if(open_max < 0 || open_max == LONG_MAX)
			open_max = 256;
	#endif
	}
	
	for(i = close_std ? 0 : 3; i<open_max; i++)
		close(i);
}

int close_fd_self()
{
	struct dirent **namelist = NULL;
	int n=0, i=0, fd=0;
	char dir[256];

	sprintf(dir, "/proc/%d/fd", getpid());

	n = scandir(dir, &namelist, 0, alphasort);
	if(n < 0)
		return -1;
	for(i=n-1; i>=0; i--)
	{
		if(0 == strcmp(".", namelist[i]->d_name)){
			free(namelist[i]);
			continue;
		}
		if(0 == strcmp("..", namelist[i]->d_name)){
			free(namelist[i]);
			continue;
		}
		fd = atoi(namelist[i]->d_name);
		free(namelist[i]);
		if(fd == 0 || fd == 1 || fd == 2)
			continue;
		close(fd);
	}

	free(namelist);
	return 0;
}

int waitpid_sec(pid_t pid, int *pstatus, unsigned int timecnt)
{
	unsigned int time_count = 0;

	if(timecnt){
		while(1){
			if(time_count >= timecnt)
				return time_count;
			if(waitpid(pid, pstatus, WNOHANG) > 0)
				return time_count;
			sleep(1);
			++time_count;
		}
	}
	else
		return waitpid(pid, pstatus, 0);
}

int waitpid_100usec(pid_t pid, int *pstatus, unsigned int timecnt)
{
	unsigned int time_count = 0;

	if(timecnt){
		while(1){
			if(time_count >= timecnt)
				return time_count;
			if(waitpid(pid, pstatus, WNOHANG) > 0)
				return time_count;
			usleep(100000);
			++time_count;
		}
	}
	else
		return waitpid(pid, pstatus, 0);
}

int create_child_process(const char *exename, char *const argv[], int close_std, int *pipefd)
{
	pid_t pid;
	int fd;

	pid = fork();
	if(pid < 0)
		return pid;
	else if(pid > 0)
		return pid;

	if(pipefd){
		dup2(pipefd[1],STDOUT_FILENO);
		dup2(pipefd[1],STDERR_FILENO);
		close(pipefd[0]);
		close(pipefd[1]);
	}

	if(close_std && !pipefd){
		fd = open("/dev/null", O_WRONLY);
		if(fd >= 0){
			if(fd != STDOUT_FILENO)
				dup2(fd, STDOUT_FILENO);
			if(fd != STDERR_FILENO)
				dup2(fd, STDERR_FILENO);
			close(fd);
		}
	}
	
	execvp(exename, argv);
	exit(1);
}

int create_child_wait_sec(const char *exename, char *const argv[], int close_std, int *pipefd, unsigned int timecnt)
{
	pid_t pid;
	int wait_cnt = 0;

	pid = create_child_process(exename, argv, close_std, pipefd);
	if(pid < 0)
		return pid;
	wait_cnt = waitpid_sec(pid, NULL, timecnt);
	if(timecnt == wait_cnt)
		kill(pid, SIGKILL);
	return wait_cnt;
}

int create_child_wait_100usec(const char *exename, char *const argv[], int close_std, int *pipefd, unsigned int timecnt)
{
	pid_t pid;
	int wait_cnt = 0;

	pid = create_child_process(exename, argv, close_std, pipefd);
	if(pid < 0)
		return pid;
	wait_cnt = waitpid_100usec(pid, NULL, timecnt);
	if(timecnt == wait_cnt)
		kill(pid, SIGKILL);
	return wait_cnt;
}

int pipe_init(int *pipefd)
{
	int fl;
	
	if( pipe(pipefd)<0 )
		return -1;

	fl = fcntl(pipefd[0], F_GETFL, 0);
	if( fl == -1 )
		return -1;
	fcntl(pipefd[0], F_SETFL, fl |O_NONBLOCK);

	fl = fcntl(pipefd[1], F_GETFL, 0);
	if( fl == -1 )
		return -1;
	fcntl(pipefd[1], F_SETFL, fl |O_NONBLOCK);

	return 0;
}

void pipe_close(int *pipefd)
{
	close(pipefd[0]);
	close(pipefd[1]);
}


// void (*exit_call)(void)    void (*exit_call)(int)
void wf_registe_exit_signal(__sighandler_t exit_call)
{
	signal(SIGINT, exit_call);/*register signal handler #include <signal.h>*/
	signal(SIGTERM, exit_call);/*register signal handler*/
	//signal(SIGQUIT, exit_call);/*register signal handler*/
}

// void (*exit_call)(void)    void (*exit_call)(int)
void wf_demon(__sighandler_t exit_call)
{
	if(fork()!= 0)
		exit(0);
	setsid();

	signal(SIGINT, exit_call);/*register signal handler #include <signal.h>*/
	signal(SIGTERM, exit_call);/*register signal handler*/
	//signal(SIGQUIT, exit_call);/*register signal handler*/
}

void wf_daemon_action(int nochdir, int noclose, __sighandler_t exit_call)
{
	int i, fd;
	pid_t pid;
	struct rlimit rl;
	struct sigaction sa;

	// clear file creation mask
	umask(0);

	if(getrlimit(RLIMIT_NOFILE, &rl) < 0)
		rl.rlim_max = 0;

	pid = fork();
	if(pid < 0)
		exit(1);
	else if(pid == 0)
		exit(0);
	else
		setsid();

	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGHUP, &sa, NULL);

	if(fork()!= 0)
		exit(0);
	
	if(!nochdir)
		chdir("/");

	if(rl.rlim_max == 0)
		close_all_fd(!noclose);
	else{
		if(rl.rlim_max == RLIM_INFINITY)
			rl.rlim_max = 1024;
		for(i = noclose ? 3 : 0; i<rl.rlim_max; i++)
			close(i);
	}

	if(!noclose){
		fd = open("/dev/null", O_WRONLY);
		if(fd >= 0){
			if(fd != STDOUT_FILENO)
				dup2(fd, STDOUT_FILENO);
			if(fd != STDERR_FILENO)
				dup2(fd, STDERR_FILENO);
			close(fd);
		}
	}

	signal(SIGINT, exit_call);
	signal(SIGTERM, exit_call);
}


int getSysCmd_output(char *cmd,char *output, unsigned int size)
{
	FILE    *read_fp;
	int        chars_read = -1;
	if(cmd == NULL || output == NULL || size == 0)
		return 0;
	memset( output, 0, size );
	read_fp = popen(cmd, "r");
	if ( read_fp != NULL )
	{
		chars_read = fread(output, sizeof(char), size, read_fp);
		pclose(read_fp);
	}

	return chars_read;
}

// <0: error;  0: not exist;  >0: number of process
int exe_exist_check(char *name)
{
	char buf[32]={'\0'}, cmd[256];

	if(!name)
		return 0;
	
	sprintf(cmd, "pidof %s |wc -w", name);
	getSysCmd_output(cmd, buf, sizeof(buf) - 1);

	return atoi(buf);
}

void wf_check_exit(int semkey, char *name)
{
	char buf[32], cmd[256];
	if(semget(semkey, 1, IPC_CREAT|0666|IPC_EXCL) < 0)
	{
		if(errno == EEXIST)
		{
			memset(buf, 0 ,sizeof(buf));
			sprintf(cmd, "pidof %s |wc -w", name);
			getSysCmd_output(cmd, buf, sizeof(buf) - 1);
			if(atoi(buf) > 1)	
			{
				printf("\n%s is exist!\n", name);
				exit(-1);
			}
		}
	}
}

static int lockfile(int fd)
{
	struct flock fl;
	fl.l_type = F_WRLCK;  /* write lock */
	fl.l_start = 0;
	fl.l_whence = SEEK_SET;
	fl.l_len = 0;  //lock the whole file
	return(fcntl(fd, F_SETLK, &fl));
}

#define LOCKMODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)
int already_running(const char *filename)
{
	int fd;
	char buf[16];

	fd = open(filename, O_RDWR | O_CREAT, LOCKMODE);
	if (fd < 0) {
		printf("can't open %s: %m\n", filename);
		exit(1);
	}

	/* 先获取文件锁 */
	if (lockfile(fd) == -1) {
		if (errno == EACCES || errno == EAGAIN) {
			printf("file: %s already locked", filename);
			close(fd);
			return 1;
		}
		printf("can't lock %s: %m\n", filename);
		exit(1);
	}

	/* 写入运行实例的pid */
	ftruncate(fd, 0);
	sprintf(buf, "%ld", (long)getpid());
	write(fd, buf, strlen(buf) + 1);
	return 0;
}


char *wf_std_error(int *errcode)
{
	if(errcode)
		*errcode = errno;
	return strerror(errno);
}

void __fprint_strn(FILE *fp, char *str, unsigned int max_num, char *startl, char *endl)
{
	if(startl)
		fprintf(fp, "%s", startl);
	while(max_num)
	{
		fprintf(fp, "%c", *str);
		++str;
		--max_num;
	}
	if(endl)
		fprintf(fp, "%s", endl);
}


void fprint_strn(FILE *fp, char *str, unsigned int max_num)
{
	__fprint_strn(fp, str, max_num, NULL, "\n");
}

void __fprint_bytes(FILE *fp, unsigned char *byte, unsigned int max_num, char *startl, char *endl)
{
	int j = 0, show_len = 0, i = 0;
	char show[16];
	if(startl)
		fprintf(fp, "%s", startl);
	while(max_num && byte)
	{
		if(j%16==0){
			for(i=0; i<show_len; i++){
				if(show[i] >= ' ' && show[i] <= '~')
					fprintf(fp, "%c", show[i]);
				else
					fprintf(fp, ".");
			}
			show_len = 0;
			fprintf(fp, "\n");
		}
		fprintf(fp, "%02X ", *byte);
		show[show_len] = (char)*byte;
		++show_len;
		++j;
		++byte;
		--max_num;
	}
	j = 16 - show_len;
	for(i=0; i<j; i++)
		fprintf(fp, "   ");
	for(i=0; i<show_len; i++){
		if(show[i] >= ' ' && show[i] <= '~')
			fprintf(fp, "%c", show[i]);
		else
			fprintf(fp, ".");
	}
	if(endl)
		fprintf(fp, "%s", endl);
}

void fprint_bytes(FILE *fp, unsigned char *byte, unsigned int max_num)
{
	__fprint_bytes(fp, byte, max_num, NULL, "\n");
}


static struct child_cmd_t *find_child_cmd(char *cmd, struct child_cmd_t *cmd_list, int cmd_size)
{
	int idx = 0;

	for(idx=0; idx<cmd_size; idx++){
		if(strcmp(cmd, cmd_list[idx].cmd) == 0){
			return &cmd_list[idx];
		}
	}
	return NULL;
}

static void default_whole_usage(struct child_cmd_t *cmd_list, int cmd_size, char *main_cmd_name, void (*whole_usage)())
{
	int idx = 0;

	if(whole_usage){
		whole_usage();
		return;
	}
	
	fprintf(stderr, "%s usage: \n"
		"\t%s [cmd] [option] [...] \n"
		"cmd list: \n"
		"  help \n"
		, main_cmd_name, main_cmd_name);

	for(idx=0; idx<cmd_size; idx++){
		fprintf(stderr, "  %s \n", cmd_list[idx].cmd);
	}
	
	fprintf(stderr, "note:\"%s help <cmd>\" for help on a specific cmd \n", main_cmd_name);

	exit(0);
}

static void child_cmd_print_usage(char *cmd, struct child_cmd_t *cmd_list, int cmd_size, char *main_cmd_name,void (*whole_usage)())
{
	struct child_cmd_t *pcmd = NULL;
	
	if(cmd == NULL){
		default_whole_usage(cmd_list, cmd_size, main_cmd_name, whole_usage);
		return;
	}
	else{
		pcmd = find_child_cmd(cmd, cmd_list, cmd_size);
	}
	if(pcmd){
		if(pcmd->usage_call)
			pcmd->usage_call();
		else
			fprintf(stderr, "no usage for %s \n\n------------------------------\n", cmd);
	}
	else
		default_whole_usage(cmd_list, cmd_size, main_cmd_name, whole_usage);
}

int wf_child_cmd(int argc, char **argv, struct child_cmd_t *cmd_list, int cmd_size, char *main_cmd_name, void (*whole_usage)())
{
	int ret=0;
	struct child_cmd_t *pcmd = NULL;
	char *p = NULL, *name = argv[0];
	int cmd_argc = argc;
	char **cmd_argv = argv;

	p = name;
	while(*p != '\0'){
		if(*p == '/')
			name = p + 1;
		++p;
	}

	if(main_cmd_name && !strcmp(name, main_cmd_name)){
		if(argc < 2 || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") ){
			default_whole_usage(cmd_list, cmd_size, main_cmd_name, whole_usage);
			return 0;
		}
		else if( strcmp(argv[1], "help") == 0 )
			child_cmd_print_usage(argv[2], cmd_list, cmd_size, main_cmd_name, whole_usage);
		else if(argv[2] && (!strcmp(argv[2], "-h") || !strcmp(argv[2], "--help")))
			child_cmd_print_usage(argv[1], cmd_list, cmd_size, main_cmd_name, whole_usage);
		else{
			cmd_argc = argc -1;
			cmd_argv = argv + 1;
			goto FIND_CMD;
		}
	}
	else{
		if( !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") ){
			child_cmd_print_usage(name, cmd_list, cmd_size, main_cmd_name, whole_usage);
		}
	}
	return 1;

FIND_CMD:
	pcmd = find_child_cmd(cmd_argv[0], cmd_list, cmd_size);
	if(!pcmd){
		default_whole_usage(cmd_list, cmd_size, main_cmd_name, whole_usage);
		return 0;
	}

	if(pcmd->init_call){
		ret = pcmd->init_call(cmd_argc, cmd_argv, pcmd);
		if(ret < 0){
			fprintf(stderr, "error: command init failed: %s \n", pcmd->cmd);
			return 1;
		}
	}
	if(pcmd->cmd_call){
		ret = pcmd->cmd_call(cmd_argc, cmd_argv);
	}
	else
		fprintf(stderr, "error: can't execute %s \n", pcmd->cmd);

	return ret;
}

int arg_parse_set_value(struct arg_parse_t *p_arg, char *data)
{
	int ret = 0;
	switch(p_arg->value_type){
	case ARG_VALUE_TYPE_CHAR:
		if(data)
			ret = sscanf(data, "%c", (char *)(p_arg->value));
		else
			*((char *)(p_arg->value)) = (char)(p_arg->set_number);
		break;
	case ARG_VALUE_TYPE_INT:
		if(data)
			ret = sscanf(data, "%d", (int *)(p_arg->value));
		else
			*((int *)(p_arg->value)) = (int)(p_arg->set_number);
		break;
	case ARG_VALUE_TYPE_LONG:
		if(data)
			ret = sscanf(data, "%ld", (long *)(p_arg->value));
		else
			*((long *)(p_arg->value)) = (long)(p_arg->set_number);
		break;
	case ARG_VALUE_TYPE_LONGLONG:
		if(data)
			ret = sscanf(data, "%lld", (long long int *)(p_arg->value));
		else
			*((long long int *)(p_arg->value)) = p_arg->set_number;
		break;
	case ARG_VALUE_TYPE_UINT:
		if(data)
			ret = sscanf(data, "%u", (unsigned int *)(p_arg->value));
		else
			*((unsigned int *)(p_arg->value)) = (unsigned int)(p_arg->set_number);
		break;
	case ARG_VALUE_TYPE_ULONG:
		if(data)
			ret = sscanf(data, "%lu", (unsigned long *)(p_arg->value));
		else
			*((unsigned long *)(p_arg->value)) = (unsigned long)(p_arg->set_number);
		break;
	case ARG_VALUE_TYPE_ULONGLONG:
		if(data)
			ret = sscanf(data, "%llu", (unsigned long long int *)(p_arg->value));
		else
			*((unsigned long long int *)(p_arg->value)) = (unsigned long long int)p_arg->set_number;
		break;
	case ARG_VALUE_TYPE_STRING:
		if(data)
			ret = sscanf(data, "%s", (char *)(p_arg->value));
 		else if(p_arg->set_string)
			strcpy((char *)(p_arg->value), p_arg->set_string);
		break;
	default:
		break;
	}

	if(data)
		return ret == 1 ? 0 : -1;
	else
		return 0;
}

int arg_parse_go(int argc, char **argv, struct arg_parse_t *arg_plist, int *new_argc, char **new_argv, struct arg_parse_hook *hook)
{
	int i = 0, ret = 0, is_match = 0;
	struct arg_parse_t *p_arg = NULL;
	struct arg_parse_hook_data hook_data;

	hook_data.argc = argc;
	hook_data.argv = argv;
	hook_data.arg_plist = arg_plist;
	hook_data.last_match = NULL;

	if(new_argc && new_argv){
		new_argv[0] = argv[0];
		*new_argc = 1;
	}

	while(argv[++i]){
		is_match = 0;
		p_arg = arg_plist;
		while(p_arg && p_arg->key){
			if((p_arg->arg_idx > 0) && (i != p_arg->arg_idx)){
				++p_arg;
				continue;
			}
			if(strcmp(argv[i], p_arg->key) == 0){
				is_match = 1;
				if(hook && hook->not_match_key)
					hook_data.last_match = p_arg;
				
				if(p_arg->has_arg){
					if(argv[++i]){
						if(p_arg->arg_deal)
							ret = p_arg->arg_deal(argv[i-1], argv[i], p_arg->value_type, p_arg->value);
						else if(p_arg->value_type > ARG_VALUE_TYPE_NONE && p_arg->value_type < ARG_VALUE_TYPE_OTHER && p_arg->value)
							ret = arg_parse_set_value(p_arg, argv[i]);
					}
				}
				else{
					if(p_arg->value_type > ARG_VALUE_TYPE_NONE && p_arg->value_type < ARG_VALUE_TYPE_OTHER && p_arg->value){
						arg_parse_set_value(p_arg, NULL);
					}
					else if(p_arg->arg_deal)
						ret = p_arg->arg_deal(argv[i], NULL, p_arg->value_type, p_arg->value);
				}
				
				if(ret < 0)
					return ret;
				break;
			}
			
			++p_arg;
		}

		if(!is_match && hook && hook->not_match_key)
			is_match = hook->not_match_key(argv[i], &hook_data, hook->not_match_key_hook_extend);
		
		if(!is_match && new_argc && new_argv){
			new_argv[*new_argc] = argv[i];
			*new_argc += 1;
		}
	}
	return 0;
}

int arg_deal_default(char *arg_key, char *arg_value, int value_type, void *value)
{
	*((char **)value) = arg_value;
	return 0;
}


#if 0
void schedule()
{
	int i=1;

	setBlueWhite();
	save_cursor();
	hide_cursor();

	for(i=1;i<=100;i++)
	{
		recover_cursor();
		printf("%d%s", i, "%");
		fflush(stdout);
		usleep(100000);
	}

	default_cursor();
	show_cursor();
}

static int sleep_tm;
void sleep_time(void *arg)
{
	int *tm = (int *)arg;
	sleep(*tm);
}

void main()
{
	int ret = -1;
	sleep_tm = 5;
	ret = run_with_timeout(3, sleep_time, &sleep_tm);
	printf("ret = %d \n", ret);
	//schedule();
	//printf("%lu \n", get_system_uptime(NULL));
}
#endif

