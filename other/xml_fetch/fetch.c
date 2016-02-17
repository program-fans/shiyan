#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#ifdef WINDOWS
#include <time.h>
#else
#include <sys/sysinfo.h>
#endif

#if 1
#define debug(fmt, ...)	printf("[%s-%d] "fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#define debug(fmt, ...)
#endif

struct str_key
{
	int flag;		// 0: invalid; 1: valid
	int type;		// 1: string; 2: string-array
	char key[64];
};

#define PREFIX_KEY_STR		"<string name="
#define SUFFIX_KEY_STR		"</string>"
#define PREFIX_KEY_STRARY	"<string-array name="
#define SUFFIX_KEY_STRARY	"</string-array>"

FILE *cn_fd, *en_fd, *out_fd;
struct str_key cn_key[3000];
int cn_key_num = -1;
char out_cache[1024][1024];
int out_cache_num = -1;
int out_line = 0, out_key = 0, del_key = 0;

long getsys_uptime(unsigned long *up_time)
{
#ifdef WINDOWS
	time_t tv;
	time(&tv);
	if(up_time)
		*up_time = (unsigned long)tv;
	return tv;
#else
	struct sysinfo info;
	memset(&info, 0, sizeof(info));
	sysinfo(&info);
	if(up_time)
		*up_time = info.uptime;

	return info.uptime;
#endif
}

int find_key(char *key, int key_type)
{
	int i=0;
	
	if(!key)
		return 0;

	for(i=0; i<=cn_key_num; i++)
	{
		if( 0 == cn_key[i].flag )
			continue;
		if( cn_key[i].type != key_type)
			continue;
		
		if( strcmp(key, cn_key[i].key) == 0 ){
			cn_key[i].flag = 0;
			//debug("%s --> invalid \n", cn_key[i].key);
			return 1;
		}
	}

	return 0;
}

int fetch_key(char *str, char *out)
{
	char *p = str;
	int find = 0, num = -1;
	
	if(!str || !out)
		return -1;

	while(*p != '\0')
	{
		if(*p == '\n' || *p == '\r')
			break;
		
		if(*p == ' ' || *p == '\t'){
			goto NEXT;
		}

		if(*p == '\"'){
			if(find)
				break;
			find = 1;
			goto NEXT;
		}

		if (*p >= '0' && *p <= '~'){
			if(find)
				out[++num] = *p;
			goto NEXT;
		}
		
	NEXT:
		++p;
	}

	if(num >= 0)
		out[++num] = '\0';

	return num;
}

int load_cn_file()
{
	char buf[1024] = {'\0'};
	char *key_pre;
	int key_type = 0, key_len = 0;
	
	while(!feof(cn_fd))
	{
		fgets(buf, sizeof(buf), cn_fd);
		if(strlen(buf) == 0)
			continue;

		key_pre = strstr(buf, PREFIX_KEY_STR);
		if(NULL == key_pre){
			key_pre = strstr(buf, PREFIX_KEY_STRARY);
			if(NULL == key_pre)
				goto LOOP_DONE;
			else{
				key_type = 2;
				key_len = fetch_key(key_pre + strlen(PREFIX_KEY_STRARY), cn_key[++cn_key_num].key);
			}
		}
		else{
			key_type = 1;
			key_len = fetch_key(key_pre + strlen(PREFIX_KEY_STR), cn_key[++cn_key_num].key);
		}

		if(key_len <= 0){
			--cn_key_num;
			goto LOOP_DONE;
		}

		cn_key[cn_key_num].flag = 1;
		cn_key[cn_key_num].type = key_type;
		//debug("key: %s \n", cn_key[cn_key_num].key);
		
	LOOP_DONE:
		key_len = 0;
		memset(buf, 0, sizeof(buf));
	}

	return cn_key_num;
}

int read_en_file()
{
	char buf[1024] = {'\0'}, key[64] = {'\0'};
	char *key_pre, *key_start, *key_end, *key_suf;
	int key_type = 0, key_len = 0;
	int multi_line = 0;
	
	while(!feof(en_fd))
	{
		fgets(buf, sizeof(buf), en_fd);
		if(strlen(buf) == 0)
			continue;

		if(multi_line){
			if(multi_line == 2){
				if( strstr(buf, SUFFIX_KEY_STRARY) )
					multi_line = 0;
			}
			else{
				if( strstr(buf, SUFFIX_KEY_STR) )
					multi_line = 0;
			}
			goto NOTHING_NEXT;
		}

		key_pre = strstr(buf, PREFIX_KEY_STR);
		if(NULL == key_pre){
			key_pre = strstr(buf, PREFIX_KEY_STRARY);
			if(NULL == key_pre)
				goto READ_NEXT;
			else{
				key_type = 2;
				key_start = key_pre + strlen(PREFIX_KEY_STRARY);
			}
		}
		else{
			key_type = 1;
			key_start = key_pre + strlen(PREFIX_KEY_STR);
		}

		key_len = fetch_key(key_start, key);
		if(key_len <= 0){
			goto READ_NEXT;
		}
		key_end = key_start + key_len;
		//debug("en_key[%d]: %s \n", key_type, key);
		if( 0 == find_key(key, key_type) ){
			if(key_type == 2)
				key_suf = strstr(key_end, SUFFIX_KEY_STRARY);
			else
				key_suf = strstr(key_end, SUFFIX_KEY_STR);

			if( !key_suf )
					multi_line = key_type;
			++del_key;
			debug("delete-key: %s \n", key);
			goto NOTHING_NEXT;
		}
		++out_key;

	READ_NEXT:
		fputs(buf, out_fd);
		++out_line;
	NOTHING_NEXT:
		key_len = 0;
		memset(buf, 0, sizeof(buf));
		memset(key, 0, sizeof(key));
	}

	return 0;
}

int main(int argc, char **argv)
{
	int ret = 0;
	long start, end;
	
	if(argc < 4){
		printf("usage: fetch <chinese-file> <english-file> <result-file> \n");
		return -1;
	}

	cn_fd = fopen(argv[1], "r");
	if(NULL == cn_fd){
		printf("error: open %s failed \n", argv[1]);
		ret = -2;
		goto ERR;
	}
	en_fd = fopen(argv[2], "r");
	if(NULL == en_fd){
		printf("error: open %s failed \n", argv[2]);
		ret = -2;
		goto ERR;
	}
	out_fd = fopen(argv[3], "w");
	if(NULL == out_fd){
		printf("error: open %s failed \n", argv[3]);
		ret = -2;
		goto ERR;
	}

	start = getsys_uptime(NULL);
	if(load_cn_file() < 0){
		printf("error: load cn-key from %s failed \n", argv[1]);
		ret = -3;
		goto ERR;
	}
	else{
		end = getsys_uptime(NULL);
		printf("fetch cn-key: %d  [%ld s] \n", cn_key_num + 1, end-start);
	}

	read_en_file();
	end = getsys_uptime(NULL);
	printf("[DONE  %ld s] delete-key: %d   out-key: %d   out-line: %d \n", end-start, del_key, out_key, out_line);

	return 0;

ERR:
	if(cn_fd)
		fclose(cn_fd);
	if(en_fd)
		fclose(en_fd);
	if(out_fd)
		fclose(out_fd);

	return ret;
}

