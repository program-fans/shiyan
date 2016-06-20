#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <stdarg.h>
#include <errno.h>

#include "wf_ipc.h"

#define BUFF_SIZE		(128)
#define PRM_TL_LEN		(sizeof(int)+sizeof(unsigned long))
#define PRM_LEN(p) 		((p)!=NULL?(p)->len+PRM_TL_LEN:0)
#define CHECK_BUFF_SIZE(length)		( ( (length+BUFF_SIZE-1)/BUFF_SIZE ) * BUFF_SIZE )

#define NTTLV_ENCODE_PUT(buff,v,l)							\
	do{														\
		memcpy( (unsigned char*)(buff),(unsigned char*)(v),l);				\
		buff+=l;											\
	}while(0)

#define NTTLV_ENCODE_PUTI(buff,v) 		NTTLV_ENCODE_PUT(buff,(&(v)),sizeof(int))	
#define NTTLV_ENCODE_PUTL(buff,v) 		NTTLV_ENCODE_PUT(buff,(&(v)),sizeof(unsigned long))
				
#define NTTLV_DECODE_GET(buff,v,l)							\
	do{														\
		memcpy( (unsigned char*)(v),(unsigned char*)(buff),l);	 			\
		(buff) = ((unsigned char*)(buff)) + l;				\
	}while(0)
	
#define NTTLV_DECODE_GETI(buff,v)			NTTLV_DECODE_GET(buff,(&(v)),sizeof(int))	
#define NTTLV_DECODE_GETL(buff,v)			NTTLV_DECODE_GET(buff,(&(v)),sizeof(unsigned long))	

typedef struct
{
	int len;
	int msg;
	int param_num; 
}nt_ipc_ctrl_header;

struct ipc_sock
{
	int sock;
	IPC_SERVER_PROC_PTR proc_ptr;
};

#define SERVER_SOCK_NUM	10

static struct ipc_sock g_server_sock[SERVER_SOCK_NUM];
static int g_num=0;

static struct ipc_sock *find_sock(int sock, int *index)
{
	int i=0;

	for(i=0; i<g_num; i++)
	{
		if( g_server_sock[i].sock == sock )
		{
			if(index)		*index = i;
			return &g_server_sock[i];
		}
	}

	return NULL;
}
static int add_sock(int sock, IPC_SERVER_PROC_PTR proc_ptr)
{
	struct ipc_sock *ipc_t = find_sock(sock, NULL);

	if(ipc_t)
		ipc_t->proc_ptr = proc_ptr;
	else
	{
		if(g_num >= SERVER_SOCK_NUM )	return -1;
		g_server_sock[g_num].sock = sock;
		g_server_sock[g_num].proc_ptr = proc_ptr;
		++g_num;
	}
	return sock;
}
static void del_sock(int sock)
{
	struct ipc_sock *ipc_t = NULL;
	int index=0;
	ipc_t = find_sock(sock, &index);
	if( !ipc_t )	return;

	memset(&g_server_sock[index], 0, sizeof(struct ipc_sock));
	memcpy(&g_server_sock[index], &g_server_sock[g_num], sizeof(struct ipc_sock));
	memset(&g_server_sock[g_num], 0, sizeof(struct ipc_sock));
	--g_num;
}
static void *get_proc_ptr_bysock(int sock)
{
	struct ipc_sock *ipc_t = NULL;

	ipc_t = find_sock(sock, NULL);
	if( !ipc_t )	return NULL;
	else		return ipc_t->proc_ptr;
}
static int ipc_read(int fd, unsigned char *buf, int total_len)
{
	int len=0, i=0, next=total_len;
	
	while(next > 0 && (len=read(fd, buf+i, next)) != next)
	{
		if(len>0)
		{
			i += len;
			next -= len;
		}
		else if(len == 0)
			break;
		else if(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			continue;
		else
			return -1;
	}

	return i;
}

static int ipc_write(int fd, unsigned char *buf, int total_len)
{
	int len=0, i=0, next=total_len;
	
	while(next > 0 && (len=write(fd, buf+i, next)) != next)
	{
		if(len>0)
		{
			i += len;
			next -= len;
		}
		else if(len == 0)
			break;
		else if(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			continue;
		else
			return -1;
	}

	return i;
}

static int ipc_check_param(scall_param **param, int param_len)
{
	int i=0;

	for(i=0;i<param_len;i++)
	{
		if(param[i]==NULL)
			continue;
		if(param[i]->type == PRM_TYPE_IN_PTR || param[i]->type == PRM_TYPE_OUT_PTR)
			if(param[i]->value == (unsigned long)NULL)	return 0;
	}
	return 1;
}

static int ipc_encode_param(scall_param **param, int param_len, void *buffer)
{
	int i=0;
	void *buff = buffer;
	
	for(i=0;i<param_len;i++)
	{
		if(param[i]==NULL)
			continue;
		NTTLV_ENCODE_PUTI(buff,param[i]->type);
		NTTLV_ENCODE_PUTL(buff,param[i]->len);
		
		if(param[i]->type == PRM_TYPE_IN_INT){
			NTTLV_ENCODE_PUTI(buff,param[i]->value);
		}
		else if (param[i]->type == PRM_TYPE_VALUE){
			NTTLV_ENCODE_PUT(buff,&param[i]->value, param[i]->len);
		}
		else{
			NTTLV_ENCODE_PUT(buff,param[i]->value,param[i]->len);
		}
	}

	return (buff - buffer);
}

static int ipc_server_encode_param(scall_param *param, int param_len, void *buffer, int *prm_len_out)
{
	int i=0, num=0;
	void *buff = buffer;
	
	for(i=0;i<param_len;i++)
	{
		if(param[i].type != PRM_TYPE_OUT_PTR)
			continue;
		
		NTTLV_ENCODE_PUTI(buff,param[i].type);
		NTTLV_ENCODE_PUTL(buff,param[i].len);
		NTTLV_ENCODE_PUT(buff,param[i].value,param[i].len);
		++num;
	}

	if(prm_len_out)	*prm_len_out = num;

	return (buff - buffer);
}

static int ipc_server_decode_param(void *buffer, int length, scall_param *param, int param_len)
{
	int i=0, num=0;
	unsigned char *buff = (unsigned char *)buffer;
	unsigned char *buffend = buff + length;
	
	for(i=0; i<param_len && buff < buffend; i++)
	{
		NTTLV_DECODE_GETI(buff,param[i].type);
		NTTLV_DECODE_GETL(buff,param[i].len);

		if(param[i].type >= PRM_TYPE_MAX)		return -1;
		
		if(param[i].type == PRM_TYPE_IN_INT || param[i].type == PRM_TYPE_VALUE)	
			NTTLV_DECODE_GET(buff, &param[i].value, param[i].len);
		else
		{
			param[i].value = (unsigned long)malloc(param[i].len);
			if(param[i].value == (unsigned long)NULL)	return -1;
			
			NTTLV_DECODE_GET(buff, param[i].value, param[i].len);
		}
		++num;
	}
	
	if(num != param_len || buff != buffend)
		return -1;
	
	return 0;
}

static int ipc_client_decode_param(void *buffer, int length, scall_param **param, int param_len)
{
	int i=0, tmp_type;
	unsigned long tmp_len;
	unsigned char *buff = (unsigned char *)buffer;
	unsigned char *buffend = buff + length;
	
	for(i=0; i<param_len && buff < buffend; i++)
	{
		if(param[i]==NULL)
			continue;
		if(param[i]->type != PRM_TYPE_OUT_PTR)
			continue;
		if(param[i]->value == (unsigned long)NULL)
			return -1;
		NTTLV_DECODE_GETI(buff,tmp_type);
		if(tmp_type != param[i]->type)
			return -1;
		NTTLV_DECODE_GETL(buff,tmp_len);
		if(tmp_len > param[i]->len)
			return -1;
		NTTLV_DECODE_GET(buff, param[i]->value, param[i]->len);
	}
	
	return 0;
}

static int ipc_server_proc(int client_sock, IPC_SERVER_PROC_PTR proc)
{
	nt_ipc_ctrl_header head;
	int ret=-1, buf_len, i, param_len;
	scall_param param[PARAM_MAX_NUM];
	unsigned char *buf=NULL;
	
	if(client_sock<0 || proc==NULL)	return -1;

	memset(param, 0, sizeof(param));
	memset(&head, 0, sizeof(head));
	if( ipc_read(client_sock, (unsigned char *)&head, sizeof(head)) < 0)
		goto END;
	
	if( head.len > 0)
	{
		buf_len = CHECK_BUFF_SIZE(head.len);
		buf = (unsigned char *)malloc(buf_len);
		if(!buf)	goto END;

		memset(buf, 0, buf_len);
		if( ipc_read(client_sock, buf, head.len) < 0 )
			goto END;

		if( ipc_server_decode_param(buf, head.len, param, head.param_num) < 0 )
			goto free_param_value;
	}

	param_len = head.param_num;
	memset(buf, 0, buf_len);

	ret = proc(head.msg, param[0].value, param[1].value, param[2].value, param[3].value);
	//ret = g_proc(head.msg, param[0].value, param[1].value, param[2].value, param[3].value);

	head.msg = ret;
	head.len = ipc_server_encode_param(param, param_len, buf, &head.param_num);
	
	if( ipc_write(client_sock, (unsigned char *)&head, sizeof(head)) < 0)
	{
		ret = -1;
		goto free_param_value;
	}
	
	if(head.len > 0)
	{
		if( ipc_write(client_sock, buf, head.len ) < 0)
		{
			ret = -1;
			goto free_param_value;
		}
	}
	
	ret = 0;
	
free_param_value:
	for(i=0; i<param_len; i++)
	{
		if(param[i].type == PRM_TYPE_IN_PTR || param[i].type == PRM_TYPE_OUT_PTR)
		{
			if(param[i].value != (unsigned long)NULL)	
				free((void *)param[i].value);
		}
	}
	
END:
	if(buf)	free(buf);
	close(client_sock);
	return ret;
}

int ipc_server_accept(int sock)
{
	struct sockaddr addr;
	socklen_t len=sizeof(addr);
	int client_sock=0;

	client_sock = accept(sock, &addr, &len);
	if(client_sock < 0)	return -1;
	
	return ipc_server_proc(client_sock, get_proc_ptr_bysock(sock));
}

int ipc_server_close(char *path, int sock)
{
	/* Unlink. */
	if(path)	unlink(path);
	del_sock(sock);
	close(sock);

	return 0;
}

int ipc_server_init(char *path, IPC_SERVER_PROC_PTR proc_ptr)
{
	struct sockaddr_un unaddr;
	int sock, len;

	if(!path || !proc_ptr)		return -1;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) 
	{
		return -1;
	}
	
	memset(&unaddr, 0, sizeof(unaddr));
	strcpy(unaddr.sun_path, path);
	unaddr.sun_family = AF_UNIX;
	len = sizeof(unaddr.sun_family) + strlen(unaddr.sun_path);
	unlink(path);

	if(bind(sock, (struct sockaddr *)&unaddr, len) < 0)
	{
		close(sock);
		return -1;
	}

	if(listen(sock, 5) < 0)
	{
		close(sock);
		return -1;
	}
	
	return add_sock(sock, proc_ptr);
}

static int ipc_client_connect(char *path)
{
	struct sockaddr_un unaddr;
	int sock, len, ret;
	
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) 
	{
		return -1;
	}

	memset(&unaddr, 0, sizeof(unaddr));
	strcpy(unaddr.sun_path, path);
	unaddr.sun_family = AF_UNIX;
	len = sizeof(unaddr.sun_family) + sizeof(unaddr.sun_path);

	while( (ret=connect(sock, (struct sockaddr *)&unaddr, len)) < 0 )
	{
		if(errno == EINTR)
			continue;
		else
		{
			close(sock);
			return ret;
		}
	}

	return sock;
}

int ipc_client_call(char *server_path, int msg, int param_len, ...)
{
	int sock, ret=0, real_length, i, buff_length;
	nt_ipc_ctrl_header head;
	va_list var_param;
	scall_param *param[PARAM_MAX_NUM] = {0};
	unsigned char *buffer = NULL;

	if(server_path == NULL || param_len > PARAM_MAX_NUM )	return -1;

	sock = ipc_client_connect(server_path);
	if(sock < 0)
	{
		return -1;
	}

	va_start(var_param, param_len);
	real_length=sizeof(msg);
	for(i=0;i<param_len;i++)
	{
		param[i] = va_arg(var_param, void *);
		real_length += PRM_LEN(param[i]);
	}
	va_end(var_param);

	if( !ipc_check_param(param, param_len) )	goto ERR;
	buff_length = CHECK_BUFF_SIZE(real_length);
	
	buffer = (unsigned char *)malloc(buff_length);
	if( !buffer )	goto ERR;
	
	head.len = ipc_encode_param(param, param_len, buffer);
	head.msg = msg;
	head.param_num = param_len;

	if( ipc_write(sock, (unsigned char *)&head, sizeof(head)) < 0 )	goto ERR;
	if(head.len > 0)
	{
		if( ipc_write(sock, buffer, head.len) < 0 )	goto ERR;
	}

	// read the data returned
	memset(&head, 0, sizeof(head));
	if( ipc_read(sock, (unsigned char *)&head, sizeof(head)) < 0)	goto ERR;
	
	ret = head.msg;
	if(head.len > 0 && head.len < buff_length && head.param_num <= param_len)
	{
		memset(buffer, 0, buff_length);
		if( ipc_read(sock, buffer, head.len) < 0)	goto ERR;
		
		ipc_client_decode_param(buffer, head.len, param, param_len);
	}

	if( buffer )	free(buffer);
	close(sock);
	return ret;

ERR:
	if( buffer )	free(buffer);
	close(sock);
	return -1;
}

#if 0

#define TEST_PATH	"/home/test_ipc"
#define pret(ret, fmt, ...)	printf(fmt" [%s  %d] \n", ##__VA_ARGS__, ret<0 ? "FAILED" : "OK", ret)
#define test_exit(name)	{printf("%s [%d] exit...\n", name, getpid());exit(0);}

void child()
{
	int ret;
	scall_param pa, pb, pc;
	char child_name[128] = "child dog";
	char parent_name[128] = "init";

	//sleep(1);
	
	ret = ipc_client_call(TEST_PATH, 48, 3, PRM_IN_INT(pa, 8), 
		PRM_IN_PTR(pb, child_name, strlen(child_name)), 
		PRM_OUT_PTR(pc, parent_name, sizeof(parent_name)));
	
	pret(ret, "ipc_client_call");

	printf("child: parent_name=[%s] \n", parent_name);

	test_exit("child");
}

int parent_call(int msg, unsigned long pa, unsigned long pb, unsigned long pc, unsigned long pd)
{
	char *child_name = (char *)pb, *parent_name = (char *)pc;
	int id = (int)pa;
	
	printf("parent: msg=%d \n", msg);
	printf("parent: id=%d \n", id);
	fflush(stdout);
	
	if(child_name)
		printf("parent: child_name=%s \n", child_name);
	if(parent_name)
		sprintf(parent_name, "%s", "parent-wolf");

	return 0;
}

void main()
{
	int ret;
	int fd;
	int max_fd;	
	fd_set fds;
	struct timeval tv;
	pid_t pid = 0;

	fd = ipc_server_init(TEST_PATH, parent_call);
	pret(fd, "ipc_server_init");
	if(fd < 0)		test_exit("parent");

	if( (pid = fork()) == 0 )
	{
		close(fd);
		child();
	}

	while(1) 
	{
		ret = ipc_server_accept(fd);
		pret(ret, "ipc_server_accept");
		break;
	}

	ipc_server_close(TEST_PATH, ret);

	waitpid(pid, NULL, 0);
	test_exit("parent");
}

#endif

