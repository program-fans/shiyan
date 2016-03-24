#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/sysinfo.h>
#include <signal.h>
#include <setjmp.h>
#include <errno.h>
#include <sys/ipc.h>
#include <dirent.h>
#include <limits.h>
#include <sys/param.h>

#include "wf_misc.h"

#define WF_ERROR_NUM_MAX		(~WF_ERROR_UNKNOW+2)
static char wf_error[WF_ERROR_NUM_MAX][128]={
	"success",
// 1 ~ 10
	"failed",
	"param error",
	"malloc error",
	"source lack",
	"space lack",
	"open error",
	"close error",
	"read error",
	"write error",
	"unknow error"
// 11 ~ 20
};

char *get_wf_error_str(int ret)
{
	return wf_error[~ret+1];
}

char *wf_std_error(int *errcode)
{
	if(errcode)
		*errcode = errno;
	return strerror(errno);
}

#if 0
/*
相关函数：longjmp, siglongjmp, setjmp
表头文件：#include <setjmp.h>
函数定义：int sigsetjmp(sigjmp_buf env, int savesigs)
函数说明：sigsetjmp()会保存目前堆栈环境，然后将目前的地址作一个记号，
而在程序其他地方调用siglongjmp()时便会直接跳到这个记号位置，然后还原堆栈，继续程序的执行。
参数env为用来保存目前堆栈环境，一般声明为全局变量
参数savesigs若为非0则代表搁置的信号集合也会一块保存
当sigsetjmp()返回0时代表已经做好记号上，若返回非0则代表由siglongjmp（）跳转回来。
返回：若直接调用则为0，若从siglongjmp调用返回则为非0

应用: 可以配合alarm闹钟实现函数超时返回
*/
static sigjmp_buf jmp_env;
static void connect_alarm(int)
{
    siglongjmp(jmp_env, 1);
}
int test_jmp()
{
	signal(SIGALRM, connect_alarm);
	if (sigsetjmp(jmp_env, 1))
	{
		printf("timeout\n");
		return 1;
	}
	alarm(3);

	sleep(5); // 执行可能超时的任务

	return 0;
}
#endif



void close_all_fd()
{
#ifdef OPEN_MAX
	long open_max = OPEN_MAX;
#else
	long open_max = 0;
#endif
	int i=0, j=0;

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
	j = (int)open_max;
	for(i=0; i<open_max; i++)
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

void wf_registe_exit_signal(__sighandler_t exit_call)
{
	signal(SIGINT, exit_call);/*register signal handler #include <signal.h>*/
	signal(SIGTERM, exit_call);/*register signal handler*/
	signal(SIGKILL, exit_call);/*register signal handler*/
}

// void (*exit_call)(void)
void wf_demon(__sighandler_t exit_call)
{
	if(fork()!= 0)
		exit(1);
	setsid();

	signal(SIGINT, exit_call);/*register signal handler #include <signal.h>*/
	signal(SIGTERM, exit_call);/*register signal handler*/
	signal(SIGKILL, exit_call);/*register signal handler*/
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

void main()
{
	schedule();
	//printf("%lu \n", get_system_uptime(NULL));
}
#endif

