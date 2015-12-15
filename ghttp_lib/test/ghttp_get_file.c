/*
 * libghttp_get.c
 *  http get test
 *  Created on: 2015-04-27
 *      Author: wolf-lone
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ghttp.h"

#define get_minus(num)	(~num + 1)

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

#define wf_return(ret)		return (~ret + 1)			// 取ret 的负数

char wf_error[WF_ERROR_NUM_MAX+1][128]={
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
	"unknow error",
// 11 ~ 20

// other
	""
};

#define set_wf_error_str(str)		strcpy(wf_error[WF_ERROR_NUM_MAX], str)

#define get_wf_error_str(ret)		wf_error[~ret + 1]

#if 1
#define pprint(fmt, ...)	printf(">> "fmt, ##__VA_ARGS__)
#else
#define pprint(fmt, ...)
#endif

void status(ghttp_request *r, char *desc)
{
      ghttp_current_status st;
      st = ghttp_get_status(r);
      pprint( "%s: %s [%d/%d]\n",
                  desc,
                  st.proc == ghttp_proc_request ? "request" :
                  st.proc == ghttp_proc_response_hdrs ? "response-headers" :
                  st.proc == ghttp_proc_response ? "response" : "none",
                  st.bytes_read, st.bytes_total);
}

int ghttp_get_file(char *path, char *url)
{
	ghttp_request *request = NULL;
	FILE * pFile=NULL;
	char *buf=NULL, *file_name = NULL;
	char new_file[256] = {'\0'};
	int ret = 0;

	ghttp_status req_status;
	int bytes_read=0,recvbytes=0;

	request = ghttp_request_new();
	if( ghttp_set_uri(request, url) < 0 )
	{
       		ret = get_minus(WF_ERROR_PARAM);
			goto END;
	}
	
	file_name = ghttp_get_resource_name(request);
	if( path && path[strlen(path)] != '/' )
		sprintf(new_file, "%s/%s", path ? path : "", file_name ? file_name : "get.html");
	else
		sprintf(new_file, "%s%s", path ? path : "", file_name ? file_name : "get.html");
	pprint("file: %s \n", new_file);
	pFile = fopen ( new_file , "wb" );
	if(pFile == NULL)
	{
		ret = get_minus(WF_ERROR_OPEN);
		goto END;
	}

	if( ghttp_set_type(request, ghttp_type_get) < 0 )//get
	{
    		ret = get_minus(WF_FAILED);
		goto END;
	}
	if (ghttp_set_sync(request, ghttp_async) < 0)
	{
		ret = get_minus(WF_FAILED);
		goto END;
	}
	if( ghttp_prepare(request) < 0 )
	{
		ret = get_minus(WF_FAILED);
		goto END;
	}
	
	do
	{
		status(request,"conn0");
		req_status = ghttp_process(request);
		if( req_status == ghttp_error )
		{
			set_wf_error_str(ghttp_get_error(request));
			ret = get_minus(WF_ERROR_NUM_MAX);
			goto END;
		}
		if (req_status != ghttp_error ) 
		{
			if( req_status == ghttp_done )	pprint("ghttp_done \n");
			ghttp_flush_response_buffer(request);
			if(ghttp_get_body_len(request) > 0)
			{
				buf = ghttp_get_body(request);
				bytes_read = ghttp_get_body_len(request);
				recvbytes += bytes_read;
				if(buf == NULL)	pprint("buf is null \n");
				pprint("bytes_read=%d, recvbytes=%d \n",bytes_read, recvbytes);
				fwrite(buf,bytes_read,1,pFile);
			}
		}
	}while (req_status == ghttp_not_done);
	
	pprint("end,  recvbytes=%d \n",recvbytes);
	
END:
	ghttp_clean(request);
	ghttp_request_destroy(request);
    	if(pFile)
		fclose(pFile);
	
	return ret;
}

int main(int argc, char **argv)
{
	int ret=0;
	
	if(argc < 2)
	{
		printf("into dyno mode... \n");
		ret = ghttp_get_file(NULL, "http://192.168.0.1/login_pc.htm");
		printf("%s \n", get_wf_error_str(ret));
		exit(0);
	}
	else if(argc == 2)
	{
		ret = ghttp_get_file(NULL, argv[1]);
	}
	else
	{
		ret = ghttp_get_file(argv[1], argv[2]);
	}

	printf("%s \n", get_wf_error_str(ret));

	return 0;
}
