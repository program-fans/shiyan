#ifndef WF_LOG_H_
#define WF_LOG_H_

enum LOG_LEVEL
{
	LOG_OFF,		//0	// 最高等级的，用于关闭所有日志打印
	LOG_FATAL,		// 1	// FATAL: 指出每个严重的错误事件将会导致应用程序的退出
	LOG_ERROR,		// 2	// ERROR: 指出虽然发生错误事件，但仍然不影响系统的继续运行
	LOG_WARN,		// 3	// WARN: 表明会出现潜在错误的情形
	LOG_INFO,		// 4	// INFO: 表明消息在粗粒度级别上突出强调应用程序的运行过程
	LOG_DEBUG,		// 5	// DEBUG: 指出细粒度信息事件对调试应用程序是非常有帮助的
	LOG_ALL		// 6	// 最低等级的，用于打开所有日志打印
};
enum LOG_SPLIT
{
	SPLIT_OFF,		// 不拆分日志
	SPLIT_DATE,		// 根据日期拆分日志文件
	SPLIT_LEVEL		// 根据日志等级拆分日志文件
};

struct wf_log_cfg
{
	char log_path[128+1];				// 日志文件存储路径，默认程序当前目录
	char logfile_suffix[5+1];			// 日志文件后缀名，默认"log"
	enum LOG_LEVEL level_show;		// 日志打印等级限制
	enum LOG_SPLIT split;			// 日志文件拆分方式
};

enum MSG_DIRECT
{
	MSG_NO,		// 不区分接收与发送
	MSG_SEND,
	MSG_RECV
};

extern void wf_set_logcfg(char *log_path, char *logfile_suffix, enum LOG_LEVEL level_show, enum LOG_SPLIT split);

//extern void wf_log(char *logname, enum LOG_LEVEL loglevel, int logtime, char *logarg, char *logbuf);

extern void WFLog(char *logname, char *file, int line, enum LOG_LEVEL loglevel, char *fmt, ...);

#define WF_LOG(logname, loglevel, fmt, ...)		WFLog(logname, __FILE__, __LINE__, loglevel, fmt, ##__VA_ARGS__)

//extern void wf_msglog_note(char *logname, char *buf);

//extern void wf_msglog(char *logname, int logtime, int isAsc, unsigned char *buf, int len);

extern void NetMsgLog(char *logname, unsigned char *buf, int len, enum MSG_DIRECT msg_direct);

extern void NetMsgLogAsc(char *logname, char *buf, int len, enum MSG_DIRECT msg_direct);

extern void NetMsgLogNote(char *logname, enum MSG_DIRECT msg_direct, char *fmt, ...);

extern void wf_print(char *file, int line, enum LOG_LEVEL loglevel, char *fmt, ...);

#define WF_PRINT(loglevel, fmt, ...)	wf_print(__FILE__, __LINE__, loglevel, ">> "fmt, ##__VA_ARGS__)

#define WF_PRINT_F(loglevel, fmt, ...)	wf_print(__FILE__, 0, loglevel, ">> "fmt, ##__VA_ARGS__)

#define WF_PRINT_L(loglevel, fmt, ...)	wf_print(NULL, __LINE__, loglevel, ">> "fmt, ##__VA_ARGS__)

#define WF_PRINT_C(loglevel, fmt, ...)	wf_print(NULL, 0, loglevel, ">> "fmt, ##__VA_ARGS__)

#define pprint(fmt, ...)	printf(">> "fmt, ##__VA_ARGS__)

extern int wf_logprint_l(char *filepath, enum LOG_LEVEL loglevel, char *fmt, ...);

#define wf_logprint(filepath, fmt, ...)		wf_logprint_l(filepath, LOG_OFF, fmt, ##__VA_ARGS__)

extern int get_param_from_file(char *file, char *tag, char *out, int maxSize);

#endif

