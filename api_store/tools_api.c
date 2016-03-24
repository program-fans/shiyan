#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>

#include "libwf.h"
#include "ghttp.h"

#define API_DEBUG_EN	1
#if API_DEBUG_EN
#define apiDebug(fmt, ...)	printf("[%s-%d] "fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define apiDebug(fmt, ...)
#endif
#define apiError(fmt, ...)	printf("api error: "fmt, ##__VA_ARGS__)

#define APIE_ERROR				11
#define APIE_MALLOC_ERROR		41
#define APIE_IO_FILE_ERROR		42
#define APIE_PARAM_ERROR		51
#define APIE_INVALID_URL		52
#define APIE_JSON_ERROR			101
#define APIE_NOT_RESULT			102
#define APIE_HTTP_ERROR			151

char *str_api_err(int api_error)
{
	static char str[128] = {'\0'};
	switch(api_error)
	{
	case 0:
		strcpy(str, "success");
		break;
	case APIE_MALLOC_ERROR:
		strcpy(str, "malloc error");
		break;
	case APIE_IO_FILE_ERROR:
		strcpy(str, "io file error");
		break;
	case APIE_PARAM_ERROR:
		strcpy(str, "param error");
		break;
	case APIE_INVALID_URL:
		strcpy(str, "invalid url");
		break;
	case APIE_JSON_ERROR:
		strcpy(str, "json error");
		break;
	case APIE_NOT_RESULT:
		strcpy(str, "no result");
		break;
	case APIE_HTTP_ERROR:
		strcpy(str, "http error");
		break;
	default:
		strcpy(str, "unknow error");
		break;
	}
	return &str[0];
}

struct key_value
{
	char key[16];
	char value[128];
};

struct api_result
{
	int http_code;
	int api_code;
	FILE *fp;
	unsigned char *buff;
	unsigned int buff_size;
	char path[256];
	unsigned char data[2048];
	unsigned int bytes;
	int finish;
	cJSON *api_ret;
	cJSON *api_data;			// the private data of api_ret
	char *api_msg;			// the msg of api code
};

struct api_t
{
	ghttp_type action;
	char name[16];
	char url[256];
	struct key_value url_param[10];
	struct key_value req_head[10];
	int url_param_num;
	int req_head_num;
	int (*result_save_func)(ghttp_request *request, struct api_t *api);
	struct api_result result;
	int api_error;
};

struct api_list
{
	int api_id;
	int (*api_init)(struct api_t *api, void *param);	// init struct api_t
	int (*api_parse)(struct api_t *api);				// parse the result of api
	int (*api_deal)(struct api_t *api);				// deal the (struct api_t)->(struct api_result).(api_ret, api_code, api_data, api_msg)
};

#define APIKEY_NAME		"apikey"
#define APIKEY_VALUE	"8f10d134932f6886ad0d38295cc4a980"

void free_api_result(struct api_result *result, int self)
{
	if(!result)
		return;
	if(result->buff != (&result->data[0]))
		free(result->buff);
	if(result->api_ret)
		cJSON_Delete(result->api_ret);
	if(self)
		free(result);
}
void free_api_t(struct api_t *api, int self)
{
	if(!api)
		return;
	free_api_result(&api->result, 0);
	if(self)
		free(api);
}

int result_save_buff(ghttp_request *request, struct api_t *api)
{
	struct api_result *result = NULL;
	char *buf = NULL;
	int bytes_read = 0;
	int tmp = 0;
	
	if(!request || !api)
		return -1;
	result = &(api->result);

	if(result->finish){
		if(result->buff_size == 0){
			api->api_error = APIE_NOT_RESULT;
		}
		return 0;
	}

	if(result->buff == NULL){
		result->buff = (unsigned char *)malloc(4096);
		if(NULL == result->buff){
			api->api_error = APIE_MALLOC_ERROR;
			return -1;
		}
		result->buff_size = 4096;
	}

	ghttp_flush_response_buffer(request);
	if(ghttp_get_body_len(request) > 0)
	{
		buf = ghttp_get_body(request);
		bytes_read = ghttp_get_body_len(request);
		//apiDebug("buf: %p, bytes_read: %d \n", buf, bytes_read);
		if(buf){
			tmp = result->bytes + bytes_read;
			if(tmp >= result->buff_size){
				bytes_read = tmp - result->bytes;
				result->finish = 1;
			}
			memcpy(result->buff + result->bytes, buf, bytes_read);
			result->bytes += bytes_read;
		}
	}

	return 0;
}

int result_save_file(ghttp_request *request, struct api_t *api)
{
	struct api_result *result = NULL;
	char *buf = NULL;
	int bytes_read = 0;
	
	if(!request || !api)
		return -1;
	result = &(api->result);

	if(result->finish){
		if(result->buff_size == 0){
			api->api_error = APIE_NOT_RESULT;
		}
		fclose(result->fp);
		return 0;
	}
	
	if(result->fp == NULL){
		if(strlen(result->path) > 0)
			result->fp = fopen ( result->path , "wb" );
		else
			result->fp = fopen ( api->name , "wb" );

		if(NULL == result->fp){
			api->api_error = APIE_IO_FILE_ERROR;
			apiError("[result fp] %s\n", wf_std_error(NULL));
			return -1;
		}
	}

	ghttp_flush_response_buffer(request);
	if(ghttp_get_body_len(request) > 0)
	{
		buf = ghttp_get_body(request);
		bytes_read = ghttp_get_body_len(request);
		
		if(buf){
			if( fwrite(buf, bytes_read, 1, result->fp) == bytes_read)
				result->bytes += bytes_read;
		}
	}

	return 0;
}

void result_recv_finish(ghttp_request *request, struct api_t *api)
{
	int ret=0;
	if(api->result.finish == 2)
		return;
	api->result.finish = 1;
	ret = api->result_save_func(request, api);
	if(ret == 0)
		api->api_error = 0;
	api->result.finish = 2;
}

int api_set_http_uri(ghttp_request *request, struct api_t *api)
{
	char url[1024] = {'\0'};
	int i=0;
	
	if(!request || !api)
		return -1;
	
	strcpy(url, api->url);
	for(i=0; i<api->url_param_num; i++){
		if(i==0)
			strcat(url, "?");
		else
			strcat(url, "&");
		strcat(url, api->url_param[i].key);
		strcat(url, "=");
		strcat(url, api->url_param[i].value);
	}

	if( ghttp_set_uri(request, url) < 0 ){
			api->api_error = APIE_INVALID_URL;
       		return -2;
	}

	return 0;
}

int api_set_http_head(ghttp_request *request, struct api_t *api)
{
	int i=0;
	
	if(!request || !api)
		return -1;

	for(i=0; i<api->req_head_num; i++){
		ghttp_set_header(request, api->req_head[i].key, api->req_head[i].value);
	}
	return 0;
}

int call_api(struct api_t *api)
{
	ghttp_request *request = NULL;
	char *buf=NULL;
	int ret = 0;

	ghttp_status req_status;
	ghttp_proc req_proc;
	int status_code=0;
	char *redirect = NULL;
#if API_DEBUG_EN
	char *tmp_pchar = NULL;
#endif
	if(!api)
		return -1;
	memset(&api->result, 0, sizeof(api->result));

	request = ghttp_request_new();
	if( api_set_http_uri(request, api) < 0 ){
       		ret = -2;
			goto END;
	}
	//apiDebug("host: %s \n", ghttp_get_host(request));
	
	if( ghttp_set_type(request, api->action) < 0 ){
    		ret = -3;
		goto END;
	}
	
	api_set_http_head(request, api);
	
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
			apiError("%s \n", ghttp_get_error(request));
			ret = -3;
			goto END;
		}
		if (req_status != ghttp_error ) 
		{
			if( req_status == ghttp_done )
			{
				status_code = ghttp_status_code(request);
				if(status_code != 200){
					result_recv_finish(request, api);
					break;
				}
			}

			req_proc = ghttp_get_proc(request);
			if( req_proc == ghttp_proc_response || req_proc == ghttp_proc_done )
			{
			#if API_DEBUG_EN
				if( !tmp_pchar )
				{
					tmp_pchar = ghttp_get_header(request, http_hdr_Content_Length);
					apiDebug("%s: %s \n", http_hdr_Content_Length, tmp_pchar ? tmp_pchar : "null");
					tmp_pchar = ghttp_get_header(request, http_hdr_Transfer_Encoding);
					apiDebug("%s: %s \n", http_hdr_Transfer_Encoding, tmp_pchar ? tmp_pchar : "null");
					tmp_pchar = ghttp_get_header(request, http_hdr_Content_Encoding);
					apiDebug("%s: %s \n", http_hdr_Content_Encoding, tmp_pchar ? tmp_pchar : "null");
					tmp_pchar = ghttp_get_header(request, http_hdr_Content_Type);
					apiDebug("%s: %s \n", http_hdr_Content_Type, tmp_pchar ? tmp_pchar : "null");
					tmp_pchar = (char *)1;
				}
			#endif
				api->result_save_func(request, api);
			}
		}
	}while (req_status == ghttp_not_done);

	api->result.http_code = status_code;
	
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
	
	result_recv_finish(request, api);
    	
	if(redirect){
		apiDebug("redirect: %s \n", redirect);
		//ret = ghttp_get_file(path, redirect);
		free(redirect);
	}
	
	if(ret == -3)
		api->api_error = APIE_HTTP_ERROR;
	
	return ret;
}


enum{
	APIID_IPLOOKUP,
	APIID_IDCARD,
	APIID_BANKCARD,
	APIID_DEF_MAX
};

#define API_LIST_MAX_NUM		100
struct api_list g_api_list[API_LIST_MAX_NUM];
int g_api_num = 0;
/*
int get_api_id()
{
	static int count = 0;
	int id = count + APIID_DEF_MAX;
	if(id >= API_LIST_MAX_NUM)
		return -1;
	++count;
	return id;
}
*/
int api_parse_defualt(struct api_t *api)
{
	struct api_result *result = NULL;
	if(!api){
		api->api_error = APIE_ERROR;
		return -1;
	}
	result = &(api->result);
		
	if(result->buff_size)
	{
		if(result->buff)
			result->api_ret = cJSON_Parse((const char *)api->result.buff);
		else if(result->fp)
			result->api_ret = cJSON_Parse_fromFp(result->fp);
	}
	
	if(result->api_ret == NULL){
		api->api_error = APIE_JSON_ERROR;
		return -1;
	}

	return 0;
}
int api_deal_defualt(struct api_t *api)
{
	struct api_result *result = NULL;
	char *out = NULL;

	if(!api){
		api->api_error = APIE_ERROR;
		return -1;
	}
	result = &(api->result);
	if(result->api_ret){
		cJSON_GetDigitValue(result->api_ret, "errNum", &result->api_code);
		result->api_msg = cJSON_GetStringValue(result->api_ret, "retMsg");
		result->api_data = cJSON_GetObjectItem(result->api_ret, "retData");
	}
	
	apiDebug("http_code: %d \n", api->result.http_code);
	apiDebug("api_code: %d \n", api->result.api_code);
	apiDebug("api_msg: %s \n", api->result.api_msg?api->result.api_msg:"null");
	if(api->result.api_data){
		out = cJSON_Print(api->result.api_data);
			if(out){
			printf("%s \n", out);
			free(out);
		}
	}
	else
		printf("[no result] \n");

	return 0;
}

int register_api(int api_id, int (*api_init)(struct api_t *api, void *param), 
	int (*api_parse)(struct api_t *api), 
	int (*api_deal)(struct api_t *api) )
{
	if(api_id<0 || !api_init || g_api_num >= API_LIST_MAX_NUM)
		return -1;
	g_api_list[api_id].api_id = api_id;
	g_api_list[api_id].api_init = api_init;
	
	if(api_parse)
		g_api_list[api_id].api_parse = api_deal;
	else
		g_api_list[api_id].api_parse = api_parse_defualt;
	
	if(api_deal)
		g_api_list[api_id].api_deal = api_deal;
	else
		g_api_list[api_id].api_deal = api_deal_defualt;
	
	++g_api_num;
	return 0;
}

static inline struct api_list *find_api(int api_id)
{
	return &g_api_list[api_id];
}

struct api_t g_api;
int exe_api(struct api_list *api, void *param)
{
	int ret = 0;
	struct api_t *apiapi = &g_api;
	
	ret = api->api_init(apiapi, param);
	if(ret < 0){
		goto END;
	}
	ret = call_api(apiapi);
	if(ret < 0){
		goto END;
	}
	ret = api->api_parse(apiapi);
	if(ret < 0){
		goto END;
	}
	ret = api->api_deal(apiapi);

END:
	apiError("%s \n", str_api_err(apiapi->api_error));
	free_api_t(apiapi, 0);

	return 0;
}


#define API_SET_APIKEY(j)	do{\
	strcpy(api->req_head[j].key, APIKEY_NAME);\
	strcpy(api->req_head[j].value, APIKEY_VALUE);\
	++j;\
	}while(0)
	
int api_init_iplookup(struct api_t *api, void *param)
{
	int i=0, j=0;
	char *ip = (char *)param;

	if(!ip || !ip_check(ip)){
		api->api_error = APIE_PARAM_ERROR;
		return -1;
	}

	memset(api, 0, sizeof(struct api_t));
	strcpy(api->url, "http://apis.baidu.com/apistore/iplookupservice/iplookup");
	strcpy(api->name, "iplookup");
	api->action = ghttp_type_get;
	
	strcpy(api->url_param[i].key, "ip");
	strcpy(api->url_param[i].value, ip);
	++i;
	api->url_param_num = i;
	strcpy(api->req_head[j].key, APIKEY_NAME);
	strcpy(api->req_head[j].value, APIKEY_VALUE);
	++j;
	//strcpy(api->req_head[j].key, http_hdr_Accept);
//	strcpy(api->req_head[j].value, "text/html");
	//++j;
	strcpy(api->req_head[j].key, http_hdr_Connection);
	strcpy(api->req_head[j].value, "keep-alive");
	++j;
	api->req_head_num = j;

	api->result_save_func = result_save_buff;

	api->result.buff = api->result.data;
	api->result.buff_size = sizeof(api->result.data);
	
	return 0;
}
		
int api_init_idcard(struct api_t *api, void *param)
{
	int i=0, j=0;
	char *idcard = (char *)param;
	
	if(!idcard || strlen(idcard)<16){
		api->api_error = APIE_PARAM_ERROR;
		return -1;
	}
	
	memset(api, 0, sizeof(struct api_t));
	strcpy(api->url, "http://apis.baidu.com/apistore/idservice/id");
	strcpy(api->name, "idcard");
	api->action = ghttp_type_get;
	
	strcpy(api->url_param[i].key, "id");
	strcpy(api->url_param[i].value, idcard);
	++i;
	api->url_param_num = i;
	strcpy(api->req_head[j].key, APIKEY_NAME);
	strcpy(api->req_head[j].value, APIKEY_VALUE);
	++j;
	API_SET_APIKEY(j);
	api->req_head_num = j;

	api->result_save_func = result_save_buff;

	api->result.buff = api->result.data;
	api->result.buff_size = sizeof(api->result.data);
}

int api_init_bankcard(struct api_t *api, void *param)
{
	int i=0, j=0;
	char *bankcard = (char *)param;
	
	if(!bankcard || strlen(bankcard)<16){
		api->api_error = APIE_PARAM_ERROR;
		return -1;
	}
	
	memset(api, 0, sizeof(struct api_t));
	strcpy(api->url, "http://apis.baidu.com/datatiny/cardinfo/cardinfo");
	strcpy(api->name, "bankcard");
	api->action = ghttp_type_get;
	
	strcpy(api->url_param[i].key, "cardnum");
	strcpy(api->url_param[i].value, bankcard);
	++i;
	api->url_param_num = i;
	strcpy(api->req_head[j].key, APIKEY_NAME);
	strcpy(api->req_head[j].value, APIKEY_VALUE);
	++j;
	API_SET_APIKEY(j);
	api->req_head_num = j;

	api->result_save_func = result_save_buff;

	api->result.buff = api->result.data;
	api->result.buff_size = sizeof(api->result.data);
}

int api_deal_bankcard(struct api_t *api)
{
	struct api_result *result = NULL;
	cJSON *api_ret = NULL;
	char *out = NULL;

	if(!api){
		api->api_error = APIE_ERROR;
		return -1;
	}
	result = &api->result;

	result->api_code = 0;
	result->api_msg = NULL;
	result->api_data = result->api_ret;
	
	apiDebug("http_code: %d \n", api->result.http_code);
	apiDebug("api_code: %d \n", api->result.api_code);
	apiDebug("api_msg: %s \n", api->result.api_msg?api->result.api_msg:"null");
	if(api->result.api_data){
		out = cJSON_Print(api->result.api_data);
			if(out){
			printf("%s \n", out);
			free(out);
		}
	}
	else
		printf("[no result] \n");

	return 0;
}

void registe_def_api()
{
	register_api(APIID_IPLOOKUP, api_init_iplookup, NULL, NULL);
	register_api(APIID_IDCARD, api_init_idcard, NULL, NULL);
	register_api(APIID_BANKCARD, api_init_bankcard, NULL, api_deal_bankcard);
}



void iplookup_usage()
{
	fprintf(stderr, "tools_api iplookup usage: \n"
		"tools_api iplookup [ip-address] \n"
		);
}
void idcard_usage()
{
	fprintf(stderr, "tools_api idcard usage: \n"
		"tools_api idcard [id-card-code] \n"
		);
}
void bankcard_usage()
{
	fprintf(stderr, "tools_api bankcard usage: \n"
		"tools_api bankcard [bank-card-code] \n"
		);
}

void api_usage()
{
	fprintf(stderr, "tools_api usage: \n"
		"\tools_api [cmd] [option] [...] \n"
		"cmd list: \n"
		"  iplookup \n"
		"  idcard \n"
		"note:\"tools_api help <cmd>\" for help on a specific cmd \n"
		);
}
void print_usage_api(char *cmd)
{
	if(cmd == NULL)
		api_usage();
	else if( strcmp(cmd, "iplookup") == 0 )
		iplookup_usage();
	else if( strcmp(cmd, "idcard") == 0 )
		idcard_usage();
	else if( strcmp(cmd, "bankcard") == 0 )
		bankcard_usage();
	else
		api_usage();
}

int cmd_api_iplookup(int argc, char **argv)
{
	int i=1, ret=0;
	char *ip = NULL;

	if(argv[++i])
		ip = argv[i];
	else
		iplookup_usage();

	return exe_api(find_api(APIID_IPLOOKUP), ip);
}

int cmd_api_idcard(int argc, char **argv)
{
	int i=1, ret=0;
	char *idcard = NULL;

	if(argv[++i])
		idcard= argv[i];
	else
		idcard_usage();
		
	return exe_api(find_api(APIID_IDCARD), idcard);
}

int cmd_api_bankcard(int argc, char **argv)
{
	int i=1, ret=0;
	char *bankcard = NULL;

	if(argv[++i])
		bankcard= argv[i];
	else
		idcard_usage();
		
	return exe_api(find_api(APIID_BANKCARD), bankcard);
}

int main(int argc, char **argv)
{
	int ret=0;

	registe_def_api();
#if 1		 //for gdb 
	exe_api(find_api(APIID_IPLOOKUP), "117.89.35.58");
	exe_api(find_api(APIID_IDCARD), "513030199310183212");
	exe_api(find_api(APIID_BANKCARD), "6216613100005090934");
#else
	if(argc >= 2)
	{
		if( strcmp(argv[1], "-h") == 0 )
			api_usage();
		else if( strcmp(argv[1], "help") == 0 )
			print_usage_api(argv[2]);
		else if( strcmp(argv[1], "iplookup") == 0 )
			ret = cmd_api_iplookup(argc, argv);
		else if( strcmp(argv[1], "idcard") == 0 )
			ret = cmd_api_idcard(argc, argv);
		else if( strcmp(argv[1], "bankcard") == 0 )
			ret = cmd_api_bankcard(argc, argv);
		else
			api_usage();
	}
	else
		api_usage();
#endif
	return ret;
}
