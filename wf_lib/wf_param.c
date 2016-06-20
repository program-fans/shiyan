#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stddef.h>
#include <fcntl.h>
#include <linux/types.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/types.h>
#include <dirent.h>

#include "wf_param.h"

#if 0
#define console_printf(fmt, ...)		printf("[%d] "fmt, __LINE__, ##__VA_ARGS__)
#define IGD_USER_MSG(fmt, ...)		printf("[%d] "fmt, __LINE__, ##__VA_ARGS__)
#else
#define console_printf(fmt, ...)
#define IGD_USER_MSG(fmt, ...)
#endif

#define igd_strcpy(dst, src)	do{\
	strncpy(dst, src, sizeof(dst)-1);\
	dst[sizeof(dst)-1] = '\0';\
}while(0)

#define CHILD_ARRAY_START "child_array_start\n"
#define CHILD_ARRAY_END "child_array_end\n"

#define NRET_TRUE	0
#define NRET_FALSE	-1

#define read_max_buf	1024*24

#ifdef  __cplusplus
extern "C" {
#endif

static char * iptostr(unsigned int  ip)
{
	struct in_addr addr;
	addr.s_addr = ip;
	return inet_ntoa(addr);
}

static int special_char_change_tobuf(char *value,char *buf, int len)
{
	char *org = buf;

	while(*value) {
		if (buf - org >= len) {
			IGD_USER_MSG("string to loog:%d\n", len);
			break;
		}
		
		if(*value == '\\' ){
			*buf++='\\';
			*buf++='\\';
		}
		else if(*value == '=') {
			*buf++='\\';
			*buf++='=';	
		}
		else if(*value == ';') {
			*buf++='\\';
			*buf++=';';	
		}
		else 
			*buf++=*value;

		value++;
	}

	org[len - 1] = 0;
	
	return 0;
		
}

static int buf_char_change_tospecial(char *value,char *buf, int len)
{
	int i = 0;
	char *org = buf;
	while(*value && ++i < len) {
		if(*value == '\\' ){
			value++;
			*buf++=*value;
		}
		else 
			*buf++=*value;
		value++;
	}

	org[len - 1] = 0;
	return 0;
		
}

static int txt_value_add_buf(char *write_buf, void *data,int len,int type,char *name)
{
	char value[1024 * 20]={0};
	char value_tmp[1024 * 20]={0};
	int i=0;
	int true_len = 0;

	switch(type) {
		case PARAM_STRING:
			true_len = strlen(data);

			if (true_len >= len)
				console_printf("%s[%d] %s....invliad string \n", __FUNCTION__, __LINE__, name);
			if (len > 1024 * 20) 
				len = 1024 * 20;
			special_char_change_tobuf(data, value_tmp, len);
			true_len=strlen(value_tmp);
			memcpy(value,value_tmp, true_len?true_len:0);
			break;
		case PARAM_RAW:
			while(i < len) {
				sprintf(value+i*3,"%02x:",((unsigned char *)(data))[i]);
				i++;
			}
			break;
		case PARAM_INT:
			sprintf(value,"%u",*(unsigned int *)data);
			break;
		case PARAM_ARRAY_INT:
			while(i<(len/sizeof(unsigned int))) {
				sprintf(value+i*9,"%08x:",((unsigned int *)(data))[i]);
				i++;
			}
			break;
		case PARAM_LONG:
			sprintf(value,"%lu",*(unsigned long *)data);
			break;
		case PARAM_LONG_LONG:
			sprintf(value,"%llu",*(unsigned long long *)data);
			break;

		case PARAM_SHORT:
			sprintf(value,"%d",*((unsigned short *)data));
			break;
		case PARAM_CHAR:
			sprintf(value,"%d",*((unsigned char *)data));
			break;
		case PARAM_STRUCT_IN_ADDR:
			sprintf(value,"%s",iptostr(*((unsigned int *)data)));
			break;
	}
	sprintf(write_buf + strlen(write_buf), "%s=%s;;",name,value);
	return 0;
}

static struct txt_list * init_txt_node(struct list_head * txt_head,char *name,unsigned long offset,struct txt_list **n)
{
		struct txt_list *node=NULL;
		int name_exit=0;
		int name_len = strlen(name);
		int cmp_name_len = name_len < sizeof(node->txt.name) ? name_len:(sizeof(node->txt.name) -1);
		list_for_each_entry(node,txt_head,list) {
			if((memcmp(node->txt.name,name, cmp_name_len) == 0) && (node->txt.offset == offset)) {
				name_exit=1;
				break;
			}
		}
		if(name_exit) {
			*n=NULL;
			return NULL;
		}
		node = (struct txt_list *)malloc(sizeof(struct txt_list ));
		if(node == NULL) {
			*n=NULL;
			return NULL;
		}
		memset(node, 0, sizeof(*node));
		INIT_LIST_HEAD(&node->list);
		memset(&(node->txt),0,sizeof(node->txt));
		*n=node;
		list_add_tail(&node->list,txt_head);
		return node;
}

static int txt_to_parame(char *data,struct txt_list *node,char *value)
{
	int j;
	unsigned char mac;
	struct in_addr addr;
	char buf[8192]={0};
	/*console_printf("star name : %s -- txtvalue %s",node->txt.name,value);*/
	switch(node->txt.type) {
		case PARAM_STRING:
			/*console_printf("star name : %s -- txtvalue %s",node->txt.name,value);*/
			buf_char_change_tospecial(value, buf, sizeof(buf));
			/*console_printf("star name : %s -- value %s",node->txt.name,buf);*/
			memcpy(data+node->txt.offset,buf,strlen(buf));
			break;
		case PARAM_RAW:
			bzero(buf,sizeof(buf));
			sprintf(buf,"%s","%02hhx:");
			j=0;	
			while(j<(node->txt.len/sizeof(unsigned char))) {
				mac = 0;
				sscanf(value+j*3,buf,&mac);
				*(unsigned char *)(data+node->txt.offset+j*sizeof(unsigned char))= mac;
		//		dbg_printf("kkkk %x     ->  %02x\n",mac,*(unsigned char *)(data+node->txt.offset+j*sizeof(unsigned char)));
				j++;
			}
			break;
		case PARAM_INT :
			*(unsigned int *)(data+node->txt.offset)=atoll(value);
			break;
		case PARAM_ARRAY_INT:
			bzero(buf,sizeof(buf));
			sprintf(buf,"%s","%08x:");
			j=0;
			while(j<(node->txt.len/sizeof(unsigned int))) {
				sscanf(value+j*9,buf,(unsigned int*)(data+node->txt.offset+j*sizeof(int)));
				j++;
			}
			break;
		case PARAM_LONG:
			*(unsigned long *)(data+node->txt.offset)=strtoull(value,NULL,10);
			break;
		case PARAM_LONG_LONG:
			*(unsigned long long *)(data+node->txt.offset)=strtoull(value,NULL,10);
			break;
		case PARAM_SHORT:
			*(int16_t *)(data+node->txt.offset)=atoi(value);
			break;
		case PARAM_CHAR:
			*(unsigned char *)(data+node->txt.offset)=atoi(value);
			break;
		case PARAM_STRUCT_IN_ADDR:
			inet_aton(value, &addr);
			*(unsigned int *)(data+node->txt.offset)=addr.s_addr;			
	}
//	console_printf("end name : %s -- txtvalue %s",node->txt.name,value);
	return 1;
}

static void txt_to_struct(struct txt_list_head * head, void *dst, void *src, int index)
{
	struct txt_list *node=NULL;
	list_for_each_entry(node, &head->member,list) {
		if (node->find) 
			memcpy((char *)dst + node->txt.offset, (char *)src + node->txt.offset, node->txt.len);
		node->find = 0;
	}
	head->init_addr2 = head->init_addr + index * head->size;
}

static int buf_to_txt(struct txt_list_head * head,char *buf, int skip)
{
	char *tp,*tp1;
	char str[8192]={0};
	char value[8192]={0};
	char param[100 * 1024] = {0, };
	char *strtp;
	struct txt_list *node=NULL;
	int i=0,j=0;
	int index = 0;
	int size = 0;
	int left = sizeof(param) - 16;

	/*  first deal index, every valid line must contain index */
	if(strncmp("array_index=", buf, strlen("array_index="))){
		console_printf("%s[%d] %s buf not begin with array_index\n", __FUNCTION__, __LINE__, buf);
		return NRET_FALSE;
	}
	if(head->size >= sizeof(param)){
		console_printf("%s[%d] struct too large, head title = %s size = %d\n", __FUNCTION__, __LINE__, head->title, head->size);
		return NRET_FALSE;
	}

	tp=buf;
	tp += strlen("array_index=");
	index = atoi(tp);

	while(left-- > 0 && *tp && *tp != ';') /*  skp index number */
		tp++;
	while(left-- > 0 && *tp && *tp == ';') /*  skip ;so reach the save param name*/
		tp++;

	if (left < 0 || !*tp) {
		console_printf("%s[%d] param invalid, head title = %s size = %d\n", __FUNCTION__, __LINE__, head->title, head->size);
		return NRET_FALSE;
	}

	while(*tp !='\n') {
		if(j > strlen(buf)) 
			return NRET_FALSE;
		j++;
		tp1=tp;
		i=0;
again:		
		if (!*tp)
			return NRET_FALSE;
		while(*tp) {
			if(*tp == '\\') {
				tp++;
				i++;
			}
			if(*tp == ';') {
				tp++;
				i++	;		
				break;
			}
			tp++;
			i++;
		}
		if(*tp == ';') {
			bzero(str,sizeof(str));
			if(!(i-1))
				goto again;
			memcpy(str,tp1,i-1);
			strtp=strstr(str,"=");
			if(!strtp)
				goto again;
			if(*(str+strlen(str)-strlen(strtp)-1) == '\\') {
				tp++;
				i++;
				goto again;
			}
		//	console_printf("star str : %s",str);
			list_for_each_entry(node, &head->member,list) {
				if((strlen(str)-strlen(strtp)) == strlen(node->txt.name)) {
					if(memcmp(node->txt.name,str,strlen(str)-strlen(strtp)) == 0) {
						if(strlen(strtp) > 1) {
							bzero(value,sizeof(value));
							size = strlen(strtp) - 1;
							if (size >= sizeof(value) - 1) 
								size = sizeof(value) - 1;
							memcpy(value,strtp+1, size);
							/*dbg_printf("name : %s =%s  offset : %d init_addr = %p init_addr2 = %p\n",node->txt.name,value,node->txt.offset, head->init_addr,
									head->init_addr2);*/
							node->find = 1;
							txt_to_parame(param ,node,value);
						}
					}
				}
			}
		//	console_printf("end str : %s",str);
		}
		else 
			goto again;
		tp++;
	}

	if(skip){
		console_printf("%s[%d] title %s skip\n" , __FUNCTION__, __LINE__, head->title);
		return NRET_TRUE;
	}

	/*  now all data is ready, write to struct */
	if(head->locate){
		return head->locate(head, param, index);
	}

	if(index >= head->mx_nr){
		if(head->move){
			return head->move(head, param);
		}
		console_printf("%s[%d] too many rule, current support %d, but the rule index is %d \n", __FUNCTION__, __LINE__, head->mx_nr, index);
		return NRET_FALSE;
	}

	/*  can write to where it was*/
	txt_to_struct(head, head->init_addr + index * head->size, param, index);
	return NRET_TRUE;
}

static int save_openparamefile(char *file)
{
	int fd;
	remove(file);
	if((fd=(open(file,O_WRONLY|O_CREAT))) < 0 ) {
		remove(file);
		return 0;
	}
	return fd;
}

static FILE * load_openparamefile(char *file)
{
	FILE *fd;
	struct stat st;

	if (stat(file, &st)) 
		return NULL;
	if (!st.st_size) 
		return NULL;
	if((fd=(fopen(file,"r"))) == NULL) {
		remove(file);
		return NULL;
	}
	return fd;
}

static int write_title(int fd, struct txt_list_head *head)
{
	char title[256] = {0, };

	snprintf(title, 256, "%s=%d", head->title, head->version);
	if(strlen(title) != write(fd, title, strlen(title)))
		return 1;	
	if(write(fd, "\n", 1) != 1)
		return 1;
	return 0;
}

static int start_write(int fd ,char *p) 
{
	if(strlen(p) != write(fd, p, strlen(p)))
		return 1;	
	return 0;
}
	
static int txt_write_parame(int fd,struct list_head *head)
{
	int i ;
	static char txt_buf[1024 * 12] = {0};
	struct txt_list_head *array_head = NULL;
	struct txt_list_head *child_array_head = NULL;
	struct txt_list *txt_head;

	list_for_each_entry(array_head,head,list) {
		bzero(txt_buf,sizeof(txt_buf));
		if(write_title(fd, array_head))
			goto error;
		for(i = 0; i < array_head->mx_nr; i++){
			if(array_head->save_check && array_head->save_check(array_head, i))/* if check error, skip. you can use this to skip useless entry*/
					continue;
			bzero(txt_buf,sizeof(txt_buf));
			txt_value_add_buf(txt_buf, &i, sizeof(i), PARAM_INT, "array_index");

			list_for_each_entry(txt_head, &array_head->member, list){
				txt_value_add_buf(txt_buf, (char *)array_head->init_addr + txt_head->txt.offset + i * array_head->size, 
						txt_head->txt.len, txt_head->txt.type, txt_head->txt.name);
			}
			/*console_printf("%s \n", txt_buf);*/
			sprintf(txt_buf + strlen(txt_buf), "\n");
			if((strlen(txt_buf)) != write(fd,txt_buf,strlen(txt_buf))) {
				goto error;
			}

			if(list_empty(&array_head->array))
				continue;
			// if array contain array, recursive invoke
			list_for_each_entry(child_array_head, &array_head->array, list){
				child_array_head->init_addr = child_array_head->offset + array_head->init_addr + i * array_head->size;
				/*console_printf("%p %p offset = %d \n", array_head->init_addr, child_array_head->init_addr, child_array_head->offset);*/
			}
			if(start_write(fd, CHILD_ARRAY_START))
				goto error;
			if(txt_write_parame(fd, &array_head->array))
				goto error;
			if(start_write(fd, CHILD_ARRAY_END))
				goto error;
		}
		if(write_title(fd, array_head))
			goto error;
	}

	return NRET_TRUE;
error:
	return NRET_FALSE;
}

static struct txt_list_head *find_txt_list_head(struct list_head *head, char *name)
{
	struct txt_list_head *list = NULL;
	int cmp_len;
	cmp_len = (int) (strchr(name,'=')? strchr(name,'=')-name:strlen(name));
	
	list_for_each_entry(list, head, list){
		if(strlen(list->title)==cmp_len && !strncmp(list->title, name,cmp_len ))
			return list;
	}
	return NULL;
}

static int txt_version_check(struct txt_list_head *head, char *buf)
{
	char *tmp;
	int version;
	
	tmp = strchr(buf, '=');
	if (!tmp) {
		IGD_USER_MSG("paramter doesn't support version \n");
		return 1;
	}
	version = atoi(tmp + 1);
	if (head->version > version) {
		IGD_USER_MSG("paramter has low version, restore default paramter \n");
		return 1;
	}
	return 0;
}

static int __txt_read_parame(FILE *fd, struct list_head *head, int parent_skip)
{
	char buf[read_max_buf] = {0};
	struct txt_list_head *array_head;
	struct txt_list_head *child_array_head;
	int j=0;
	int child_skip = parent_skip , skip = parent_skip;

	while(1) {
		bzero(buf,sizeof(buf));
		if(!fgets(buf,read_max_buf,fd)) {
			return NRET_TRUE;
		}
		
		if(!memcmp(buf, CHILD_ARRAY_END, strlen(CHILD_ARRAY_END)))
			return NRET_TRUE;
		if((array_head = find_txt_list_head(head, buf)) != NULL) { /*  first find array title  */
			j=0;
			if (txt_version_check(array_head, buf)) {
				if (array_head->para_reinit) 
					array_head->para_reinit();
				skip = 1;
				child_skip = 1;
			}
			while(1) {
				bzero(buf,sizeof(buf));
				if(!fgets(buf,read_max_buf,fd)) {
					return NRET_FALSE;
				}
				if(!memcmp(buf, array_head->title, strlen(array_head->title))) {/* goto next array param */
					skip = parent_skip;
					child_skip = parent_skip;
					break;
				}
				if(!memcmp(buf, CHILD_ARRAY_START, strlen(CHILD_ARRAY_START))){
					list_for_each_entry(child_array_head, &array_head->array, list){
						child_array_head->init_addr = array_head->init_addr2 + child_array_head->offset;
						/*child_array_head->init_addr2 = array_head->init_addr2;*/
					}
					if(__txt_read_parame(fd, &array_head->array, child_skip) != NRET_TRUE)
						return NRET_FALSE;
				}else{
					if (buf_to_txt(array_head, buf, skip)) {/* if find error , skip all subsequent child rule */
						child_skip = 1;
						/*  doesn't need return false, lose rule is acceptable than restore default*/
					}
				}
				j++;
			}
		}
		else{
			console_printf("%s[%d] %s not find \n", __FUNCTION__, __LINE__, buf);

            /* skip this extra param */
	        char extra_head_title[read_max_buf] = {0};
            igd_strcpy(extra_head_title, buf);

            while (1) {
				bzero(buf,sizeof(buf));
				if(!fgets(buf,read_max_buf,fd)) {
					return -3;
				}

                if (!strcmp(buf, extra_head_title))
                    break;
            }
		}
	}
	return NRET_TRUE;
}

static int txt_read_parame(FILE *fd,struct list_head *head)
{
	if(fseek(fd,0,SEEK_SET) !=0) {
		return NRET_FALSE;
	}
	if(__txt_read_parame(fd, head, 0))
		return NRET_FALSE;
	return NRET_TRUE;
}




void txt_head_set_version(struct txt_list_head *txt, int version)
{
	txt->version = version;
}

struct list_head *  txt_add(struct list_head *txt_head,char *name,unsigned int len,char type,unsigned long offset)  
{
	struct txt_list *txt_node=NULL;	 
	int copy_len = 0;

	init_txt_node(txt_head,name,offset,&txt_node);	
	if(txt_node == NULL)			
		return txt_head;			
	if(strlen(name) >= sizeof(txt_node->txt.name))
		copy_len = sizeof(txt_node->txt.name) - 1;
	else
		copy_len = strlen(name);

	memcpy(txt_node->txt.name, name, copy_len);		
	txt_node->txt.len=len;			
	txt_node->txt.type=type;		
	txt_node->txt.offset=offset;		
	return txt_head;
} 

struct txt_list_head *txt_head_add(struct list_head *head, void *addr, char *title, int mx_nr, int size)
{
	struct txt_list_head *list;
	list = malloc(sizeof(struct txt_list_head));
	if(list == NULL){
		console_printf("%s........NO MEM \n", __FUNCTION__);
		goto error;
	}		
	memset(list, 0, sizeof(*list));
	strncpy(list->title, title, sizeof(list->title) - 1);
	INIT_LIST_HEAD(&list->list);
	INIT_LIST_HEAD(&list->member);
	INIT_LIST_HEAD(&list->array);
	list->mx_nr = mx_nr;
	list->size = size;
	list->init_addr = addr;
	list_add_tail(&list->list, head);
	return list;
error: 
	return NULL;
}

int wf_generic_load_param(char *name, struct list_head *head, void (*restore)(void))
{
	int ret = NRET_FALSE;
	FILE *fp = NULL;

	fp = load_openparamefile(name);

	if(!fp)
		goto errout;

	ret = txt_read_parame(fp, head);
	fclose(fp);

errout:
	/*  if read error, restore default */
	if (ret != NRET_TRUE ) {
		IGD_USER_MSG("%s read error, restore default \n", name);
		if (restore)
			(*restore)();
	}
	return ret;
}

int wf_generic_save_param(char *name, struct list_head *head)
{
	int ret = NRET_TRUE;
	int fd;

	fd = save_openparamefile(name);
	if(!fd){
		ret = NRET_FALSE;
		goto out;
	}
	ret = txt_write_parame(fd, head);
	close(fd);
out:
	if(ret == NRET_FALSE)
		 remove(name);
	return ret;
}

void  free_txt_list_head(struct list_head *head)
{
	struct txt_list_head *node=NULL,*tmp_node=NULL;
	list_for_each_entry_safe(node,tmp_node, head,list) {
		if(!list_empty(&node->array))
			free_txt_list_head(&node->array);
		list_del(&node->list);
		free(node);
	}
	INIT_LIST_HEAD(head);
	return ;
}

#if 0
int main(int args, char **argv)
{
	return 0;
}
#endif

