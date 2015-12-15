#ifndef WF_MISC_H_
#define WF_MISC_H_

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



extern int wf_get_selfexe_path(char *path, int len);

extern long wf_getsys_uptime(unsigned long *up_time);
#ifndef get_system_uptime
#define get_system_uptime(up_time)	wf_getsys_uptime(up_time)
#endif

#include <signal.h>
extern void wf_registe_exit_signal(__sighandler_t exit_call);
// void (*exit_call)(void)
extern void wf_damen(__sighandler_t exit_call);

extern int getSysCmd_output(char *cmd,char *output, unsigned int size);
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
enum WF_ERROR_VALUE
{
	WF_SUCCESS,
// 1 ~ 10
	WF_FAILED,
	WF_ERROR_PARAM,
	WF_ERROR_MALLOC,
	WF_ERROR_SOURCE_LACK,					// 资源缺乏
	WF_ERROR_SPACE_LACK,						// 空间缺乏，程序设计上所限定的空间
												// 区别于WF_ERROR_MALLOC
	WF_ERROR_OPEN,
	WF_ERROR_CLOSE,
	WF_ERROR_READ,
	WF_ERROR_WRITE,
	WF_ERROR_UNKNOW,
// 11 ~ 20	
	WF_ERROR_NUM_MAX
};

#define wf_return(ret)		return (~ret + 1)			// 取ret 的相反数

extern char wf_error[WF_ERROR_NUM_MAX][128];

#define get_wf_error_str(ret)		wf_error[~ret + 1]

#endif
// -------------------------------------------------------------------

#endif

