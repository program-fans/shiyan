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
#define APIE_RESULT_PARSE		103
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
		strcpy(str, "result parse json error");
		break;
	case APIE_NOT_RESULT:
		strcpy(str, "no result");
		break;
	case APIE_RESULT_PARSE:
		strcpy(str, "result parse error");
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
	struct slist_node node;
	char key[128];
	char value[4096];
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
	unsigned int bytes;		// the size of result that saved in buff or fp
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
	struct slist_head url_param;
	struct slist_head req_head;
	int (*result_save_func)(ghttp_request *request, struct api_t *api);
	struct api_result result;
	void *private;
	int api_error;
};

struct api_list
{
	int api_id;
	int (*api_init)(struct api_t *api, void *param);	// init struct api_t, and assign (struct api_t)->private
	int (*api_parse)(struct api_t *api);				// parse the result of api
	int (*api_deal)(struct api_t *api);				// deal the (struct api_t)->(struct api_result).(api_ret, api_code, api_data, api_msg)
	void (*api_free)(struct api_t *api);				// free (struct api_t)->private
};

#define APIKEY_NAME		"apikey"
#define APIKEY_VALUE	"8f10d134932f6886ad0d38295cc4a980"

inline void free_key_value_list(struct slist_head *list)
{
	struct key_value *pos = NULL;

	if(slist_empty(list))
		return;
	slist_while_get_head_entry(pos, list, node)
		free(pos);
}
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
	free_key_value_list(&api->url_param);
	free_key_value_list(&api->req_head);
	free_api_result(&api->result, 0);
	api->private = NULL;
	if(self)
		free(api);
}

int set_api_url_param(struct api_t *api, char *key, char *value)
{
	struct key_value *p = (struct key_value *)malloc(sizeof(struct key_value));
	if(!p){
		api->api_error = APIE_MALLOC_ERROR;
		return -1;
	}
	memset(p, 0, sizeof(struct key_value));
	strcpy_array(p->key, key);
	strcpy_array(p->value, value);
	slist_add(&api->url_param, &p->node);
	return 0;
}

int set_api_req_head(struct api_t *api, char *key, char *value)
{
	struct key_value *p = (struct key_value *)malloc(sizeof(struct key_value));
	if(!p){
		api->api_error = APIE_MALLOC_ERROR;
		return -1;
	}
	memset(p, 0, sizeof(struct key_value));
	strcpy_array(p->key, key);
	strcpy_array(p->value, value);
	slist_add(&api->req_head, &p->node);
	return 0;
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
	char *url = NULL;
	int i=0, len=0;
	struct key_value *pos = NULL;
	
	if(!request || !api)
		return -1;

	len = strlen(api->url);
	slist_for_each_entry(pos, &api->url_param, node){
		len += strlen(pos->key);
		len += strlen(pos->value);
		len += 2;
	}
	url = (char *)malloc(len+1);
	if(!url){
		api->api_error = APIE_MALLOC_ERROR;
		return -1;
	}
	
	strcpy(url, api->url);
	slist_for_each_entry(pos, &api->url_param, node){
		if(i==0)
			strcat(url, "?");
		else
			strcat(url, "&");
		strcat(url, pos->key);
		strcat(url, "=");
		strcat(url, pos->value);
		++i;
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
	struct key_value *pos = NULL;
	
	if(!request || !api)
		return -1;

	slist_for_each_entry(pos, &api->req_head, node){
		ghttp_set_header(request, pos->key, pos->value);
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
					tmp_pchar = (char *)ghttp_get_header(request, "Content-Length");
					apiDebug("Content-Length: %s \n", tmp_pchar ? tmp_pchar : "null");
					tmp_pchar = (char *)ghttp_get_header(request, "Transfer-Encoding");
					apiDebug("Transfer-Encoding: %s \n", tmp_pchar ? tmp_pchar : "null");
					tmp_pchar = (char *)ghttp_get_header(request, "Content-Encoding");
					apiDebug("Content-Encoding: %s \n", tmp_pchar ? tmp_pchar : "null");
					tmp_pchar = (char *)ghttp_get_header(request, "Content-Type");
					apiDebug("Content-Type: %s \n", tmp_pchar ? tmp_pchar : "null");
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
	APIID_IPLOOKUP,		// ip 归属地查询
	APIID_IDCARD,			// 身份证信息查询
	APIID_BANKCARD,		// 银行卡信息查询
	APIID_PHONE,			// 手机号码信息查询
	APIID_QRCODE,			// 二维码生成
	APIID_QQ,				// QQ 信息查询
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

	apiDebug("result->bytes: %u \n", result->bytes);
	if(result->bytes)
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
void api_free_defualt(struct api_t *api)
{
	if(api && api->private)
		free(api->private);
}

int register_api(int api_id, int (*api_init)(struct api_t *api, void *param), 
	int (*api_parse)(struct api_t *api), 
	int (*api_deal)(struct api_t *api), 
	void (*api_free)(struct api_t *api) )
{
	if(api_id<0 || !api_init || g_api_num >= API_LIST_MAX_NUM)
		return -1;
	g_api_list[api_id].api_id = api_id;
	g_api_list[api_id].api_init = api_init;
	
	if(api_parse)
		g_api_list[api_id].api_parse = api_parse;
	else
		g_api_list[api_id].api_parse = api_parse_defualt;
	
	if(api_deal)
		g_api_list[api_id].api_deal = api_deal;
	else
		g_api_list[api_id].api_deal = api_deal_defualt;

	if(api_free)
		g_api_list[api_id].api_free= api_free;
	else
		g_api_list[api_id].api_free = api_free_defualt;
	
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
	api->api_free(apiapi);
	free_api_t(apiapi, 0);

	return 0;
}


int api_init_iplookup(struct api_t *api, void *param)
{
	int i=0, j=0;
	char *api_param = (char *)param;

	if(!api_param|| !ip_check(api_param)){
		api->api_error = APIE_PARAM_ERROR;
		return -1;
	}

	memset(api, 0, sizeof(struct api_t));
	strcpy_array(api->url, "http://apis.baidu.com/apistore/iplookupservice/iplookup");
	strcpy_array(api->name, "iplookup");
	api->action = ghttp_type_get;

	if(set_api_url_param(api, "ip", api_param) < 0)
		goto ERR;
	if(set_api_req_head(api, APIKEY_NAME, APIKEY_VALUE) < 0)
		goto ERR;
	//if(set_api_req_head(api, http_hdr_Accept, "text/html") < 0)
	//	goto ERR;
	if(set_api_req_head(api, (char *)http_hdr_Connection, "keep-alive") < 0)
		goto ERR;

	api->result_save_func = result_save_buff;

	api->result.buff = api->result.data;
	api->result.buff_size = sizeof(api->result.data);
	
	return 0;
ERR:
	api->api_error = APIE_MALLOC_ERROR;
	return -1;
}
		
int api_init_idcard(struct api_t *api, void *param)
{
	int i=0, j=0;
	char *api_param = (char *)param;

	if(!api_param || strlen(api_param) < 18){
		api->api_error = APIE_PARAM_ERROR;
		return -1;
	}

	memset(api, 0, sizeof(struct api_t));
	strcpy_array(api->url, "http://apis.baidu.com/apistore/idservice/id");
	strcpy_array(api->name, "idcard");
	api->action = ghttp_type_get;

	if(set_api_url_param(api, "id", api_param) < 0)
		goto ERR;
	if(set_api_req_head(api, APIKEY_NAME, APIKEY_VALUE) < 0)
		goto ERR;

	api->result_save_func = result_save_buff;

	api->result.buff = api->result.data;
	api->result.buff_size = sizeof(api->result.data);
	
	return 0;
ERR:
	api->api_error = APIE_MALLOC_ERROR;
	return -1;
}

int api_init_bankcard(struct api_t *api, void *param)
{
	int i=0, j=0;
	char *api_param = (char *)param;

	if(!api_param || strlen(api_param) < 16){
		api->api_error = APIE_PARAM_ERROR;
		return -1;
	}

	memset(api, 0, sizeof(struct api_t));
	strcpy_array(api->url, "http://apis.baidu.com/datatiny/cardinfo/cardinfo");
	strcpy_array(api->name, "bankcard");
	api->action = ghttp_type_get;

	if(set_api_url_param(api, "cardnum", api_param) < 0)
		goto ERR;
	if(set_api_req_head(api, APIKEY_NAME, APIKEY_VALUE) < 0)
		goto ERR;

	api->result_save_func = result_save_buff;

	api->result.buff = api->result.data;
	api->result.buff_size = sizeof(api->result.data);
	
	return 0;
ERR:
	api->api_error = APIE_MALLOC_ERROR;
	return -1;
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

int api_init_phone(struct api_t *api, void *param)
{
	int i=0, j=0;
	char *api_param = (char *)param;

	if(!api_param || strlen(api_param) < 8){
		api->api_error = APIE_PARAM_ERROR;
		return -1;
	}

	memset(api, 0, sizeof(struct api_t));
	strcpy_array(api->url, "http://apis.baidu.com/apistore/mobilenumber/mobilenumber");
	strcpy_array(api->name, "phone");
	api->action = ghttp_type_get;

	if(set_api_url_param(api, "phone", api_param) < 0)
		goto ERR;
	if(set_api_req_head(api, APIKEY_NAME, APIKEY_VALUE) < 0)
		goto ERR;

	api->result_save_func = result_save_buff;

	api->result.buff = api->result.data;
	api->result.buff_size = sizeof(api->result.data);
	
	return 0;
ERR:
	api->api_error = APIE_MALLOC_ERROR;
	return -1;
}

struct param_qrcode
{
	int size;
	char jpg_path[256];
	char qr_string[2048];
};

int api_init_qrcode(struct api_t *api, void *param)
{
	int i=0, j=0;
	char size_str[4] = "8", qr_str[2560] = {'\0'};
	int size = 8;
	struct param_qrcode *api_param = (struct param_qrcode *)param;
	
	if(!api_param || strlen(api_param->qr_string)<=0){
		api->api_error = APIE_PARAM_ERROR;
		return -1;
	}
	if(api_param->size >= 1 && api_param->size <= 20)
		size = api_param->size;
	sprintf(size_str, "%d", size);
	urlencode((unsigned char *)(api_param->qr_string), (unsigned char *)qr_str);
	
	memset(api, 0, sizeof(struct api_t));
	strcpy_array(api->url, "http://apis.baidu.com/3023/qr/qrcode");
	strcpy_array(api->name, "qrcode");
	api->action = ghttp_type_get;

	if(strlen(api_param->jpg_path) > 0){
		api->private = (void *)strdup(api_param->jpg_path);
		if(NULL == api->private)
			goto ERR;
	}
	if(set_api_url_param(api, "size", size_str) < 0)
		goto ERR;
	if(set_api_url_param(api, "qr", qr_str) < 0)
		goto ERR;
	if(set_api_req_head(api, APIKEY_NAME, APIKEY_VALUE) < 0)
		goto ERR;

	api->result_save_func = result_save_buff;

	api->result.buff = api->result.data;
	api->result.buff_size = sizeof(api->result.data);
	
	return 0;
ERR:
	api->api_error = APIE_MALLOC_ERROR;
	return -1;
}
int api_deal_qrcode(struct api_t *api)
{
	struct api_result *result = NULL;
	cJSON *api_ret = NULL;
	char *out = NULL, *qr_jpg_url = NULL, *qr_jpg_path = NULL;
	char tmp[32] = "./api_qr.jpg";

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
		qr_jpg_url = cJSON_GetStringValue(api->result.api_data, "url");
		if(qr_jpg_url){
			if(api->private)
				qr_jpg_path = (char *)api->private;
			else
				qr_jpg_path = &tmp[0];
			if( ghttp_download_file(qr_jpg_path, qr_jpg_url) < 0)
				printf("qr_jpg download failed \n");
			else{
				printf("qr_jpg download OK [%s] \n", qr_jpg_path);
				return 0;
			}
		}
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

int api_init_qq(struct api_t *api, void *param)
{
	int i=0, j=0;
	char *api_param = (char *)param;

	if(!api_param || strlen(api_param) < 5){
		api->api_error = APIE_PARAM_ERROR;
		return -1;
	}

	memset(api, 0, sizeof(struct api_t));
	strcpy_array(api->url, "http://apis.baidu.com/3023/qq/qq");
	strcpy_array(api->name, "qq");
	api->action = ghttp_type_get;

	if(set_api_url_param(api, "uins", api_param) < 0)
		goto ERR;
	if(set_api_req_head(api, APIKEY_NAME, APIKEY_VALUE) < 0)
		goto ERR;

	api->result_save_func = result_save_buff;

	api->result.buff = api->result.data;
	api->result.buff_size = sizeof(api->result.data);
	
	return 0;
ERR:
	api->api_error = APIE_MALLOC_ERROR;
	return -1;
}

int api_parse_qq(struct api_t *api)
{
	char *json_str = NULL;
	struct api_result *result = NULL;
	if(!api){
		api->api_error = APIE_ERROR;
		return -1;
	}
	result = &(api->result);

	apiDebug("result->bytes: %u \n", result->bytes);
	if(result->bytes && result->buff){
		json_str = strchr((char *)result->buff, '(');
		if(json_str){
			++json_str;
			result->api_ret = cJSON_Parse(json_str);
		}
		else{
			api->api_error = APIE_RESULT_PARSE;
			return -1;
		}

		if(result->api_ret == NULL){
			api->api_error = APIE_JSON_ERROR;
			return -1;
		}
	}

	return 0;
}

int api_deal_qq(struct api_t *api)
{
	int i=0, j=0;
	char *tmp, *name, png_path[128], nickname[32]={'\0'};
	cJSON *obj;
	struct api_result *result = NULL;
	if(!api){
		api->api_error = APIE_ERROR;
		return -1;
	}
	result = &(api->result);

	result->api_code = 0;
	result->api_msg = NULL;
	result->api_data = result->api_ret;
	
	apiDebug("http_code: %d \n", api->result.http_code);
	apiDebug("api_code: %d \n", api->result.api_code);
	apiDebug("api_msg: %s \n", api->result.api_msg?api->result.api_msg:"null");

	if(result->api_data)
	{
		j = cJSON_GetArraySize(result->api_data);
		printf("QQ  [%d] \n", j);
		for(i=0; i<j; i++)
		{
			obj = cJSON_GetArrayItem(result->api_data, i);
			if(obj){
				name = cJSON_GetObjectName(obj);
				printf("%s\n", name ? name : "unknown QQ");
				tmp = cJSON_GetStringValue(cJSON_GetArrayItem(obj, 0), NULL);
				if(tmp && name){
					sprintf(png_path, "%s.png", name);
					if(ghttp_download_file(png_path, tmp) < 0)
						printf("\ticon: download failed [%s]\n", tmp);
					else
						printf("\ticon: %s [download OK]\n", png_path);
				}
				else
					printf("\ticon: %s\n", tmp ? tmp : "null");

				tmp = cJSON_GetStringValue(cJSON_GetArrayItem(obj, 6), NULL);
				if(tmp){
					name = &nickname[0];
					gbk_to_utf8(tmp, strlen(tmp), &name, NULL);
					printf("\tnickname: %s\n", nickname);
				}
				else
					printf("\tnickname: null \n");
			}
		}
	}
	else
		printf("[no result] \n");

	return 0;
}

void registe_def_api()
{
	register_api(APIID_IPLOOKUP, api_init_iplookup, NULL, NULL, NULL);
	register_api(APIID_IDCARD, api_init_idcard, NULL, NULL, NULL);
	register_api(APIID_BANKCARD, api_init_bankcard, NULL, api_deal_bankcard, NULL);
	register_api(APIID_PHONE, api_init_phone, NULL, NULL, NULL);
	register_api(APIID_QRCODE, api_init_qrcode, NULL, api_deal_qrcode, NULL);
	register_api(APIID_QQ, api_init_qq, api_parse_qq, api_deal_qq, NULL);
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
void phone_usage()
{
	fprintf(stderr, "tools_api phone usage: \n"
		"tools_api phone [phone-number] \n"
		);
}
void qrcode_usage()
{
	fprintf(stderr, "tools_api qrcode usage: \n"
		"tools_api qrcode [--qr qr-string] [--jpg qr-jpg-path] [--size 1-20] \n"
		);
}
void qq_usage()
{
	fprintf(stderr, "tools_api qq usage: \n"
		"tools_api \"qq\" [qq-number,qq-number,...] \n"
		);
}

void api_usage()
{
	fprintf(stderr, "tools_api usage: \n"
		"\tools_api [cmd] [option] [...] \n"
		"cmd list: \n"
		"  iplookup \n"
		"  idcard \n"
		"  bankcard \n"
		"  phone \n"
		"  qrcode \n"
		"  qq \n"
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
	else if( strcmp(cmd, "phone") == 0 )
		phone_usage();
	else if( strcmp(cmd, "qrcode") == 0 )
		qrcode_usage();
	else if( strcmp(cmd, "qq") == 0 )
		qq_usage();
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
int cmd_api_phone(int argc, char **argv)
{
	int i=1, ret=0;
	char *phone = NULL;

	if(argv[++i])
		phone= argv[i];
	else
		phone_usage();
		
	return exe_api(find_api(APIID_PHONE), phone);
}
int cmd_api_qrcode(int argc, char **argv)
{
	int i=1, ret=0;
	struct param_qrcode param;
	char *phone = NULL;

	while(argv[++i])
	{
		if( strcmp(argv[i], "--qr") == 0 && argv[++i]){
			strcpy_array(param.qr_string, argv[i]);
		}
		else if( strcmp(argv[i], "--jpg") == 0 && argv[++i]){
			strcpy_array(param.jpg_path, argv[i]);
		}
		else if( strcmp(argv[i], "--size") == 0 && argv[++i]){
			sscanf(argv[i], "%x", &param.size);
		}
		else{
			printf("invalid param: %s \n", argv[i]);
			qrcode_usage();
			return -1;
		}
	}
	
	return exe_api(find_api(APIID_QRCODE), &param);
}
int cmd_api_qq(int argc, char **argv)
{
	int i=1, ret=0;
	char *qq = NULL;

	if(argv[++i])
		qq= argv[i];
	else
		phone_usage();
		
	return exe_api(find_api(APIID_QQ), qq);
}

int main(int argc, char **argv)
{
	int ret=0;

	registe_def_api();
#if 0		 //for gdb 
/*	exe_api(find_api(APIID_IPLOOKUP), "117.89.35.58");
	exe_api(find_api(APIID_IDCARD), "513030199310183212");
	exe_api(find_api(APIID_BANKCARD), "6216613100005090934");
	exe_api(find_api(APIID_PHONE), "13678165275");
	struct param_qrcode param;
	param.size = 8;
	strcpy_array(param.qr_string, "http://www.baidu.com/index.php?ch=en&var=abc#frag2");
	strcpy_array(param.jpg_path, "/mnt/hgfs/share/tmp/api_qr.jpg");
	exe_api(find_api(APIID_QRCODE), &param);*/
	exe_api(find_api(APIID_QQ), "897319259,1129231447");
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
		else if( strcmp(argv[1], "phone") == 0 )
			ret = cmd_api_phone(argc, argv);
		else if( strcmp(argv[1], "qrcode") == 0 )
			ret = cmd_api_qrcode(argc, argv);
		else if( strcmp(argv[1], "qq") == 0 )
			ret = cmd_api_qq(argc, argv);
		else
			api_usage();
	}
	else
		api_usage();
#endif
	return ret;
}
