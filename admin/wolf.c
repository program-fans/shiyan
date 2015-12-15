#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

	sprintf(g_cmg_buf, "kill -9 `pidof %s`", name);
	ret = system(g_cmg_buf);
	printf("ret of system: %d \n", ret);
}

int main(int argc, char **argv)
{
	int i=0, ret=0;
	scall_param pa, pb;
	
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

