#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>

#include "libwf.h"

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
void wf_sock_test()
{
	int sock;
	int client_sock;

	sock = wf_listen_socket(80, 1);
	if(sock < 0)
	{
		printf("wf_listen_socket error \n");
		exit(0);
	}

	while(1)
	{
		client_sock = wf_accept(sock, NULL, NULL);
		if( client_sock < 0)
			continue;
		printf("have client connect \n");
	}
}
void wf_p_app_test(int argc, char **argv)
{
	int sock;
	int ret;
	char buf[1024]={'\0'};
	char ip[16]={'\0'};

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock < 0){
		printf("%s \n", wf_socket_error(NULL));
		return;
	}

	if(argv[1])
		sprintf(ip, "%s", argv[1]);
	else
		sprintf(ip, "%s", "192.168.0.1");
	ret = wf_sendto_ip(sock, "test local", strlen("test local"), 0, ip, 48480);
	WF_PVAR_INT(ret);
	if(ret < 0){
		printf("%s \n", wf_socket_error(NULL));
		return;
	}

	wf_recvfrom(sock, buf, 1024, 0, NULL);

	printf("recv: %s \n", buf);
}
// ------------------------------------------------------------
void bubble_sort()
{
#define TOTAL	10
	int a[TOTAL] = {56, 84, 5, 854, 24, 0, 5, 45, 0, 48};
	int i, j, k;
	int start = 2, end=9;	// start index ~ end index
	
	for(i=start+1; i<end; i++)
	{
		for(j=start; j<end+1+start-i; j++)
		{
			if(a[j] > a[j+1])
			{
				//printf("%d <-> %d \n", j, j+1);
				k = a[j];
				a[j] = a[j+1];
				a[j+1] = k;
			}
		}
	}

	for(i=0; i<TOTAL; i++)
		printf("%d ", a[i]);
	printf("\n");

	for(i=start; i<end+1; i++)
		printf("%d ", a[i]);
	printf("\n");
}
// ------------------------------------------------------------
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
	int i=0;
	char s[128] = "dsagsdga";
	strrev(s);

	//printf("i"" = ""%d"" \n", i);
	WF_PVAR_INT(i);
}

void main(int argc, char **argv)
{
	//test();
	//char_test();
	//wf_sock_test();

	wf_p_app_test(argc, argv);
	//ipc_test();
}



