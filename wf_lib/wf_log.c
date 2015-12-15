/* 
	该程序用来记录日志
	帮助程序员调试
	创建时间：2015年3月8日
	修改时间：2015年9月1日
	版本：SCO_V3.0
*/

#include    <stdio.h>
#include    <time.h>
#include    <stdarg.h>
#include    <string.h>
#include    <stdlib.h>

#include "wf_log.h"

static char level_str[LOG_ALL+1][10]={"", "FATAL", "ERROR", "WARN", "INFO", "DEBUG", ""};
static struct wf_log_cfg wf_cfg={"./", "log", LOG_ALL, SPLIT_DATE};

void wf_set_logcfg(char *log_path, char *logfile_suffix, enum LOG_LEVEL level_show, enum LOG_SPLIT split)
{
	int len=0;
	
	if( log_path == NULL )	sprintf(wf_cfg.log_path, "%s", "./");	// sprintf(wf_cfg.log_path, "%s", getenv("HOME"));
	else
	{
		len = strlen(log_path);
		if( len >= 128 )	sprintf(wf_cfg.log_path, "%s", "./");
		else
		{
			if( log_path[len-1] != '/' )	sprintf(wf_cfg.log_path, "%s/", log_path);
			else		sprintf(wf_cfg.log_path, "%s", log_path);
		
		}
	}

	if( logfile_suffix == NULL )	sprintf(wf_cfg.logfile_suffix, "%s", "log");
	else
	{
		len = strlen(logfile_suffix);
		if( len >= 5 )	sprintf(wf_cfg.logfile_suffix, "%s", "log");
		else		sprintf(wf_cfg.logfile_suffix, "%s", logfile_suffix);
	}

	wf_cfg.level_show = level_show;
	wf_cfg.split = split;
}

static void deal_logname(int isMsg, enum LOG_LEVEL loglevel, struct tm *local_t, char *src, char *dst)
{
	char buf[32];
		
	if(src == NULL)	sprintf(dst,"%s%s", wf_cfg.log_path, isMsg ? "msg" : "wf_log");
	else		sprintf(dst,"%s%s", wf_cfg.log_path, src);

	if(isMsg)
	{
		sprintf(buf,"_%02d%02d.%s", local_t->tm_mon+1, local_t->tm_mday, wf_cfg.logfile_suffix);
		strcat(dst, buf);
		return;
	}
	
	switch(wf_cfg.split)
	{
	case SPLIT_DATE:
		sprintf(buf,"_%02d%02d.%s", local_t->tm_mon+1, local_t->tm_mday, wf_cfg.logfile_suffix);
		break;
	case SPLIT_LEVEL:
		sprintf(buf,"_%s.%s", level_str[loglevel], wf_cfg.logfile_suffix);
		break;
	case SPLIT_OFF:
		sprintf(buf,".%s", wf_cfg.logfile_suffix);
		break;
	}
	strcat(dst, buf);
}

void wf_log(char *logname, enum LOG_LEVEL loglevel, int logtime, char *logarg, char *logbuf)
{
	FILE *fp;
	time_t tv;
	struct tm *local_t;
	char logfile[256];

//	if( loglevel > wf_cfg.level_show )	return;

	time(&tv);
	local_t=localtime(&tv);

	deal_logname(0, loglevel, local_t, logname, logfile);
	
	fp=fopen(logfile,"a+");
	if(fp==NULL) return;

	if( logtime)
	{
		fprintf ( fp, "%02d-%02d %d:%d:%d ",
		local_t->tm_mon+1,local_t->tm_mday,
		local_t->tm_hour,local_t->tm_min,local_t->tm_sec);
	}

	if(logarg)	fprintf(fp, "%s: %s", level_str[loglevel], logarg);
	else		fprintf(fp, "%s: ", level_str[loglevel]);

	if(logbuf)	fprintf(fp, "%s\n", logbuf);
	else		fprintf(fp, "\n");

	fflush(fp);
	fclose ( fp );
}

/*
	file：__FILE__
	line：__LINE__
	fmt：格式
*/
void WFLog(char *logname, char *file, int line, enum LOG_LEVEL loglevel, char *fmt, ...)
{
	char buf[1024], logarg[128];
	va_list args;

	va_start(args,fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	sprintf (logarg, "[%s][%d] ",file, line);

	wf_log(logname, loglevel, 1, logarg, buf);
}

void wf_msglog_note(char *logname, char *buf)
{
	FILE *fp;
	time_t tv;
	struct tm *local_t;
	char logfile[256];

	time(&tv);
	local_t=localtime(&tv);

	deal_logname(1, LOG_ALL, local_t, logname, logfile);

	fp=fopen(logfile,"a+");
	if(fp==NULL) return;

	if(buf)	fprintf(fp,"%s\n", buf);
	else		fprintf(fp,"\n");

	fflush(fp);
	fclose(fp);
}

void wf_msglog(char *logname, int logtime, int isAsc, unsigned char *buf, int len)
{
	int j=0;
	FILE *fp;
	time_t tv;
	struct tm *local_t;
	char logfile[256];
	char *asc = (char *)buf;
	
	time(&tv);
	local_t=localtime(&tv);

	deal_logname(1, LOG_ALL, local_t, logname, logfile);
	
	fp=fopen(logfile,"a+");
	if(fp==NULL) return;

	if(logtime)
	{
		fprintf(fp,"\n%04d.%02d.%02d-%02d:%02d:%02d %s", 
			local_t->tm_year+1900, local_t->tm_mon+1, local_t->tm_mday,
			local_t->tm_hour, local_t->tm_min, local_t->tm_sec, isAsc ? "\n" : "");
	}
	else		fprintf(fp,"%s", isAsc ? "\n" : "");
	for(j=0 ;j<len; j++)
	{
		if(isAsc)
		{
			fputc(asc[j], fp);
		}
		else
		{
			if(j%16==0)	fprintf(fp,"\n");
			fprintf(fp,"%02x  ",buf[j]);
		}
	}
	fprintf(fp,"\n\n");

	fflush(fp);
	fclose(fp);
}
static void deal_msglogname(enum MSG_DIRECT msg_direct, char *src, char *dst)
{
	switch(msg_direct)
	{
	case MSG_NO:
		sprintf(dst, "%s", src);
		break;
	case MSG_RECV:
		sprintf(dst, "%s_recv", src);
		break;
	case MSG_SEND:
		sprintf(dst, "%s_send", src);
		break;
	}
}
void NetMsgLog(char *logname, unsigned char *buf, int len, enum MSG_DIRECT msg_direct)
{
	char filename[200];

	deal_msglogname(msg_direct, logname, filename);
	wf_msglog(filename, 1, 0, buf, len);
}
void NetMsgLogAsc(char *logname, char *buf, int len, enum MSG_DIRECT msg_direct)
{
	char filename[200];

	deal_msglogname(msg_direct, logname, filename);
	wf_msglog(filename, 1, 1, (unsigned char *)buf, len);
}

void NetMsgLogNote(char *logname, enum MSG_DIRECT msg_direct, char *fmt, ...)
{
	char filename[200];
	char buf[1024];
	va_list args;

	va_start(args,fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	deal_msglogname(msg_direct, logname, filename);
	wf_msglog_note(logname, buf);
}

void wf_print(char *file, int line, enum LOG_LEVEL loglevel, char *fmt, ...)
{
	char buf[2048],level[10];
	va_list args;

	if( loglevel > wf_cfg.level_show )	return;
	
	va_start(args,fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);
	
	if(file && line>0)	printf("%s:[%s][%d]%s\n",level_str[loglevel], file, line, buf );
	else if(file && line<=0)		printf("%s:[%s]%s\n",level_str[loglevel], file, buf );
	else if(!file && line>0)		printf("%s:[%d]%s\n",level_str[loglevel], line, buf );
	else		printf("%s:%s\n",level_str[loglevel], buf );
}

int wf_logprint_l(char *filepath, enum LOG_LEVEL loglevel, char *fmt, ...)
{
	FILE *fp = NULL;
	va_list args;

	if(filepath == NULL)
		return -1;

	fp = fopen(filepath, "a+");
	if(fp == NULL)
		return -1;

	fprintf(fp, "%s: ", level_str[loglevel]);
	va_start(args,fmt);
	vfprintf(fp, fmt, args);
	va_end(args);

	fclose(fp);
	return 0;
}

int get_param_from_string(char *buf, char *tag, char *out, int maxSize)
{
// 没想好，暂时不用此函数
	int str_len;
	int i=0, taglen=0, outlen = 0, outsize = maxSize - 1;
	char *pout = out;

	if(buf == NULL || tag == NULL || (out && maxSize <= 0))
		return -1;
	
	str_len = strlen(buf);
	taglen = strlen(tag);
	if(taglen >= str_len)
		return -4;
	
	if(memcmp(buf, tag, taglen) == 0)
	{
		i=taglen;
		while (1)
		{
			if ( i >= str_len )
				goto END;
			if(buf[i] == '\n' || buf[i] == '\r')
				goto END;
			
			if (buf[i] != ' ' && buf[i] != '\t')
				break;
			else
				++i;
		}
		while (1)
		{
			if ( i >= str_len )
				goto END;
			if (buf[i] >= ' ' && buf[i] <= '~')
			{
				++outlen;
				if(out)
				{
					*pout++ = buf[i++];
					if( outlen >= outsize )
						goto END;
				}
			}
			else
				break;
		}
	}
	
END:
	if(out)
		out[outlen >= outsize ? outsize : outlen] = '\0';
	
	return outlen;
}

int get_param_from_file(char *file, char *tag, char *out, int maxSize)
{ 
#define LINE_MAX	128

	char buf[LINE_MAX+1];
	FILE *fp;
	int i=0, taglen=0, outlen = 0, outsize = maxSize - 1;
	char *pout = out;

	if(file == NULL || tag == NULL || (out && maxSize <= 0))
		return -1;

	taglen = strlen(tag);
	if(taglen >= LINE_MAX)
		return -4;
	
	fp = fopen(file,"r");
	if(fp == NULL)	
		return -2;	
	
	while(1)
	{
		memset(buf,0x00,sizeof(buf));
		if(fgets(buf,sizeof(buf),fp) == NULL) 
		{
			fclose(fp);
			return -3;
		}

		if(buf[0] == '#')			// '#' 开头的行视为注释行
			continue;
		if(memcmp(buf,tag,taglen) == 0)
		{
			i=taglen;
			while (1)
			{
				if ( i >= LINE_MAX )
					goto END;
				if(buf[i] == '\n' || buf[i] == '\r')
					goto END;
				
				if (buf[i] != ' ' && buf[i] != '\t')
					break;
				else
					++i;
			}
			while (1)
			{
				if ( i >= LINE_MAX )
					goto END;
				if (buf[i] >= ' ' && buf[i] <= '~')		// if (buf[i] >= '!' && buf[i] <= '~')
				{
					++outlen;
					if(out)
					{
						*pout++ = buf[i++];
						if( outlen >= outsize )
							goto END;
					}
				}
				else
					break;
			}
			break;
		}
	}

END:
	if(out)
		out[outlen >= outsize ? outsize : outlen] = '\0';
	fclose(fp);
	return outlen;
}

#if 0
#define LOG_PATH	"./testlog/"
#define LOG_FILE_NAME	"test"

void main()
{
	char buf[1024] = "this is test info";

	wf_set_logcfg(LOG_PATH, NULL, LOG_ALL, SPLIT_DATE);

	WF_LOG(LOG_FILE_NAME, LOG_DEBUG, "this is test info");

	NetMsgLog("test_msg", buf, strlen(buf), MSG_RECV);
	NetMsgLog("test_msg", buf, strlen(buf), MSG_SEND);
	NetMsgLog("test_msg", buf, strlen(buf), MSG_NO);

	NetMsgLogNote("test_msg", MSG_NO, "this is test note 1");
	NetMsgLogNote("test_msg", MSG_NO, "this is test note 2");
	NetMsgLog("test_msg", buf, strlen(buf), MSG_NO);

	NetMsgLogAsc("test_asc_msg", buf, strlen(buf), MSG_RECV);
	NetMsgLogAsc("test_asc_msg", buf, strlen(buf), MSG_SEND);
	NetMsgLogAsc("test_asc_msg", buf, strlen(buf), MSG_NO);

	NetMsgLogNote("test_asc_msg", MSG_NO, "this is test note 1");
	NetMsgLogNote("test_asc_msg", MSG_NO, "this is test note 2");
	NetMsgLogAsc("test_asc_msg", buf, strlen(buf), MSG_NO);

	WF_PRINT(LOG_DEBUG, "this is test info");
}
#endif

