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
	pprint("%s\n", str); \
	pprint("exit: %s [%d] \n", __FILE__, __LINE__); \
	exit(0); \
} while (0)
#endif


#ifndef get_opposite
#define get_opposite(num)	(~num + 1)		// 取num 的相反数
#endif

#ifndef get_integer
#define get_integer(num, n)	(((num+n-1)/n)*n)
#endif






extern int close_fd_self();
#define close_fd_parent()	close_fd_self()

extern void bubble_sort_char(char *str, int start_index, int end_index);
extern void bubble_sort_int(int *num, int start_index, int end_index);

extern void alarm_start(unsigned int seconds, void (*func)(int));


extern void alarm_again(unsigned int seconds);

extern void alarm_cancel();

extern int wf_kill_exe(int pid, char *name);
extern int wf_get_selfexe_path(char *path, int len);

extern long wf_getsys_uptime(unsigned long *up_time);
#ifndef get_system_uptime
#define get_system_uptime(up_time)	wf_getsys_uptime(up_time)
#endif

#include <signal.h>
extern void wf_registe_exit_signal(__sighandler_t exit_call);
// void (*exit_call)(void)
extern void wf_demon(__sighandler_t exit_call);

extern int getSysCmd_output(char *cmd,char *output, unsigned int size);
extern int exe_exist_check(char *name);
extern void wf_check_exit(int semkey, char *name);


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

// -------------------------------------------------------------------
extern char *wf_std_error(int *errcode);

#ifndef WF_ERROR
#define WF_ERROR

#define WF_SUCCESS					0
// 1 ~ 10
#define WF_FAILED					-1
#define WF_ERROR_PARAM			-2
#define WF_ERROR_MALLOC			-3
#define WF_ERROR_SOURCE_LACK		-4			// 资源缺乏
#define WF_ERROR_SPACE_LACK		-5			// 空间缺乏，程序设计上所限定的空间
												// 区别于WF_ERROR_MALLOC
#define WF_ERROR_OPEN				-6
#define WF_ERROR_CLOSE				-7
#define WF_ERROR_READ				-8
#define WF_ERROR_WRITE				-9
#define WF_ERROR_UNKNOW			-10
// 11 ~ 20	

extern char *get_wf_error_str(int ret);

#endif
// -------------------------------------------------------------------

#endif

