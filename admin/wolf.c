#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

#include "libwf.h"

struct wolf_app
{
	char *name;
	char *path;
};

struct wolf_app apps[]={
	{"net_monitor", "/home/net_monitor_ipc"},
	{"arp_cheat", NULL},
	{"arp_turn", NULL},
	{NULL, NULL},
};

struct wolf_app *g_app = NULL;
char g_cmg_buf[1024] = {'\0'};
char g_result_buf[2048] = {'\0'};

struct wolf_app *find_app(char *name)
{
	int i=0;

	while(1)
	{
		if(apps[i].name == NULL)
			break;
		if(strcmp(apps[i].name, name) == 0)
		{
			g_app = &apps[i];
			return g_app;
		}
		++i;
	}

	return NULL;
}

void kill_app(char *name)
{
	int ret;
	if( find_app(name) == NULL )
		return;

	sprintf(g_cmg_buf, "kill -2 `pidof %s`", name);
	//sprintf(g_cmg_buf, "kill -9 `pidof %s`", name);
	ret = system(g_cmg_buf);
	printf("ret of system: %d \n", ret);
}

int w_ipc_sock;
int ipc_call(int msg, unsigned long pa, unsigned long pb, unsigned long pc, unsigned long pd)
{
	return 2333;
}

int sock;
void damen_process()
{
	int len=0;
	char buf[2048]={'\0'};
	struct sockaddr_in addr_from;

	sock = wf_udp_socket(48480, 0, NULL);
	if(sock < 0){
		printf("%s \n", wf_socket_error(NULL));
		return;
	}

	while(1)
	{
		len = wf_recvfrom(sock, buf, 2048, 0, &addr_from);
		WF_PVAR_INT(len);
		if(len < 0){
			printf("%s \n", wf_socket_error(NULL));
			return;
		}

		printf("recv: %s \n", buf);

		wf_sendto(sock, "test OK", strlen("test OK"), 0, &addr_from);
	}
}

void exit_call(int a)
{
	if(w_ipc_sock > 0)
		ipc_server_close("/home/wolf_ipc", w_ipc_sock);
	if(sock > 0)
		close(sock);
	exit(0);
}

int main(int argc, char **argv)
{
	int i=0, ret=0;
	scall_param pa, pb;

	wf_registe_exit_signal(exit_call);
	if( argv[1] && strcmp(argv[1], "-s") == 0)
	{
		damen_process();
		exit_call(0);
	}

	if( argv[1] && strcmp(argv[1], "--ipc") == 0)
	{
		w_ipc_sock = ipc_server_init("/home/wolf_ipc", ipc_call);
		ipc_server_accept(w_ipc_sock);
		exit_call(0);
	}
	
	if(argc < 3)
		goto CMD_ERR;

	if( strcmp(argv[1], "kill") == 0)
	{
		for(i=2; i<argc; i++)
			kill_app(argv[i]);
		return 0;
	}

	if( find_app(argv[1]) == NULL )
	{
		printf("app is unknow \n");
		return 0;
	}

	memset(g_cmg_buf, 0, sizeof(g_cmg_buf));
	memset(g_result_buf, 0, sizeof(g_result_buf));

	strcpy(g_cmg_buf, argv[2]);
	for(i=3; i<argc; i++)
	{
		strcat(g_cmg_buf, " ");
		strcat(g_cmg_buf, argv[i]);
	}
	printf("CMD: %s \n", g_cmg_buf);

	ret = ipc_client_call(g_app->path, 0, 2, 
		PRM_IN_PTR(pa,g_cmg_buf,strlen(g_cmg_buf)+1), 
		PRM_OUT_PTR(pb,g_result_buf,sizeof(g_result_buf)));

	printf("ret=%d \n", ret);
	printf("%s\n", g_result_buf);
	
	return 0;

CMD_ERR:
	printf("cmd error, nothing to do \n");
	return 0;
}

