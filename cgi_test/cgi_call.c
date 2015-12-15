#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ghttp.h"


int call_cgi()
{
	ghttp_request *request = NULL;
	ghttp_status req_status;
	char *buf;
	int bytes_read;
	int status_code;

	request = ghttp_request_new();
	if( ghttp_set_uri(request, "http://192.168.0.1/app/devices/webs/getdeviceslist.cgi") < 0 )
	{
       	printf("ghttp_set_uri error \n");
		goto END;
	}
	if( ghttp_set_type(request, ghttp_type_post) < 0 )//get
	{
    		printf("ghttp_set_type error \n");
		goto END;
	}
	ghttp_set_header(request, "Accept", "application/json, text/javascript, */*; q=0.01");
	ghttp_set_header(request, "Accept-Encoding", "gzip,deflate,sdch");
	ghttp_set_header(request, "Accept-Language", "zh-CN,zh;q=0.8");
	ghttp_set_header(request, "Connection", "keep-alive");
	ghttp_set_header(request, "Cookie", "downlater=true; Qihoo_360_login=4cc35ec358992fcba06a9a6baf199ae4");
	ghttp_set_header(request, "token_id", "7ad9f7ca19444e2aef61e285ebcec5c0");
	ghttp_set_header(request, "X-Requested-With", "XMLHttpRequest");
	ghttp_set_header(request, "Referer", "http://192.168.0.1/new_index.htm?token_id=7ad9f7ca19444e2aef61e285ebcec5c0");

	if (ghttp_set_sync(request, ghttp_async) < 0)
	{
		printf("ghttp_set_sync error \n");
		goto END;
	}
	if( ghttp_prepare(request) < 0 )
	{
		printf("ghttp_prepare error \n");
		goto END;
	}

	do
	{
		req_status = ghttp_process(request);
		if( req_status == ghttp_error )
		{
			printf("error: %s \n", ghttp_get_error(request));
			goto END;
		}
		if (req_status != ghttp_error ) 
		{
			ghttp_flush_response_buffer(request);
			if(ghttp_get_body_len(request) > 0)
			{
				buf = ghttp_get_body(request);
				bytes_read = ghttp_get_body_len(request);
				if(buf != NULL)
					printf("%s", buf);
			}

			if( req_status == ghttp_done )
			{
				status_code = ghttp_status_code(request);
				printf("status code: %d \n", status_code);

				if(status_code == 302)
				{
					printf("Location: %s \n", ghttp_get_header(request, "Location"));
				}
			}
		}
	}while (req_status == ghttp_not_done);

END:
	ghttp_clean(request);
	ghttp_request_destroy(request);

	return 0;
}

int main(int argc, char **argv)
{
	call_cgi();

	return 0;
}
