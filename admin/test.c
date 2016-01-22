#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>

#include "libwf.h"
#include "ghttp.h"

enum{
	OFF_GDB,
	GDB_test,
	GDB_char,
	GDB_ipc,
	GDB_slist,
	GDB_httpget
};

int gdb_ctrl = OFF_GDB;

static unsigned char globel_buf[4096] = {0};

void slist_test()
{
struct test_t
{
        int a;
        struct slist_node slist;
};
	struct slist_head test_list, new_list;
	struct test_t *p = NULL, *pos = NULL;
	int i=0;
		
	INIT_SLIST_HEAD(&test_list); 
	INIT_SLIST_HEAD(&new_list); 
	for(i=0; i<10; i++)
	{
		p = (struct test_t *)malloc(sizeof(struct test_t));
		if( p == NULL)
		{
			--i;
			continue;
		}
		p->a = i;
		slist_add(&test_list, &p->slist);
	}
	slist_del_head(&test_list); 
	slist_del_head(&test_list); 

	for(i=10; i<15; i++)
	{
		p = (struct test_t *)malloc(sizeof(struct test_t));
		if( p == NULL)
		{
			--i;
			continue;
		}
		p->a = i;
		slist_add(&new_list, &p->slist);
	}

	slist_splice_init(&new_list, &test_list);

	slist_for_each_entry(pos, &test_list, slist)
		printf("%d ", pos->a);
	printf("\n");

	slist_for_each_entry(pos, &new_list, slist)
		printf("%d ", pos->a);
	printf("\n");
}

void ipc_test()
{
	int ret;
	
	ret = ipc_client_call("/home/wolf_ipc", 0, 0);
	WF_PVAR_INT(ret);
}
void char_test()
{
	printf("%s \n", time2str_pformat(time(NULL), NULL, "<now: %Y/%M/%D  ## %h:%m:%s >", 64));
	printf("%s \n", timenow2str(NULL));
}
void test()
{
	#define TOTAL	10
	int a[12] = {56, 84, 5, 854, 24, 0, 5, 45, 0, 48, 486, 42};
	int i, j, k;

	for(i=0; i<TOTAL; i++)
		printf("%d\t", i);
	printf("\n");
	for(i=0; i<TOTAL; i++)
		printf("%d\t", a[i]);
	printf("\n");
	
	bubble_sort_int(a, 0, 9);

	for(i=0; i<TOTAL; i++)
		printf("%d\t", a[i]);
	printf("\n");
}

int ghttp_get_file(char *path, char *url)
{
	ghttp_request *request = NULL;
	FILE * pFile=NULL;
	char *buf=NULL, *file_name = NULL;
	int ret = 0;

	ghttp_status req_status;
	int bytes_read=0,recvbytes=0;
	int status_code=0;
	char *redirect = NULL;

	request = ghttp_request_new();
	if( ghttp_set_uri(request, url) < 0 ){
			printf("invalid url: %s \n", url);
       		ret = -1;
			goto END;
	}
	file_name = ghttp_get_resource_name(request);
	if(path)
		pFile = fopen ( path , "wb" );
	else if(file_name)
		pFile = fopen ( file_name , "wb" );
	else
		pFile = fopen ( "httpget.html" , "wb" );
	if(pFile == NULL){
		printf("error: %s \n", wf_std_error(NULL));
		ret = -2;
		goto END;
	}
	if( ghttp_set_type(request, ghttp_type_get) < 0 ){
    		ret = -3;
		goto END;
	}
	if (ghttp_set_sync(request, ghttp_async) < 0){
		ret = -3;
		goto END;
	}
	if( ghttp_prepare(request) < 0 ){
		ret = -3;
		goto END;
	}

	do
	{
		req_status = ghttp_process(request);
		if( req_status == ghttp_error ){
			printf("%s \n", ghttp_get_error(request));
			ret = -4;
			goto END;
		}
		if (req_status != ghttp_error ) 
		{
			if( req_status == ghttp_done )
			{
				status_code = ghttp_status_code(request);
				if(status_code != 200){
					fclose(pFile);
					pFile = NULL;
					break;
				}
			}
			
			ghttp_flush_response_buffer(request);
			if(ghttp_get_body_len(request) > 0)
			{
				buf = ghttp_get_body(request);
				bytes_read = ghttp_get_body_len(request);
				recvbytes += bytes_read;
				if(buf)
					fwrite(buf,bytes_read,1,pFile);
			}
		}
	}while (req_status == ghttp_not_done);

	ret = status_code;
	switch(status_code)
	{
	case 200:
	default:
		break;
	case 302:
		buf = (char *)ghttp_get_header(request, "Location");
		if(buf){
			redirect = (char *)malloc(strlen(buf)+1);
			if(redirect == NULL){
				ret = -1;
				goto END;
			}
			strcpy(redirect, buf);
		}
		break;
	}
	
END:
	ghttp_clean(request);
	ghttp_request_destroy(request);
    	if(pFile)
		fclose(pFile);
	if(redirect){
		printf("redirect: %s \n", redirect);
		ret = ghttp_get_file(path, redirect);
		free(redirect);
	}
	
	return ret;
}

int test_httpget(int argc, char **argv)
{
	int i=1;
	char *path=NULL, *url = NULL;
	int ret=0;
	printf("----------- test httpget ----------\n");

	while(argv[++i])
	{
		if( strcmp(argv[i], "-O") == 0 && argv[++i])
			path = argv[i];
		else{
			url = argv[i];
			break;
		}
	}

	if(gdb_ctrl == GDB_httpget)
		ret = ghttp_get_file("httpget_gdb.html", "http://www.baidu.com");
	else
		ret = ghttp_get_file(path, url);
	if(ret < 0)
		printf("failed get [%d] \n", ret);
	else if(ret == 0 || ret == 200)
		printf("get done [%d] \n", ret);
	else
		printf("code: %d \n", ret);

	return ret;
}

int main(int argc, char **argv)
{
	int ret=0;

	switch(gdb_ctrl)
	{
	case GDB_httpget:
		ret = test_httpget(argc, argv);
		return ret;
		break;
	case OFF_GDB:
	default:
		break;
	}

	if(argc >= 2)
	{
		if( strcmp(argv[1], "char") == 0 )
			char_test();
		else if( strcmp(argv[1], "ipc") == 0 )
			ipc_test();
		else if( strcmp(argv[1], "slist") == 0 )
			slist_test();
		else if( strcmp(argv[1], "httpget") == 0 )
			ret = test_httpget(argc, argv);
		else
			test();
	}
	else{
		test();
	}

	return ret;
}



