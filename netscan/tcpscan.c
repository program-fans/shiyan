#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <arpa/inet.h>  //for in_addr   inet_ntoa
#include "net_packet.h"
#include "netscan.h"

#if 1
#define DEBUG(fmt, ...)	do{if(1)printf("[%s-%d] "fmt, __FILE__, __LINE__, ##__VA_ARGS__);}while(0)
#else
#define DEBUG(fmt, ...)	do{}while(0)
#endif
#if 1
#define ERROR(fmt, ...)	do{if(1)printf(fmt, ##__VA_ARGS__);}while(0)
#else
#define ERROR(fmt, ...)	do{}while(0)
#endif


#define MULITITHREAD_NUM			15

enum tcpscan_type
{
	TSCAN_TYPE_CONNECT,
	TSCAN_TYPE_SYN
};

struct tcpscan_t
{
	struct netscan_t scan;
	enum tcpscan_type type;
	struct netscan_result *result;
	struct threadpool *tdpool;
};

struct tscan_task
{
	unsigned int addr;
	unsigned short port;
	struct tcpscan_t *tscan;
};

struct sockaddr_in g_localaddr;
struct tcpscan_t g_tscan;
struct netscan_result g_result;

int set_localaddr()
{
	unsigned int local_addr = 0;
	unsigned short port = 0;
	if(get_netdev_addr("eth0", &local_addr) < 0){
		ERROR("get_netdev_addr error \n");
		return -1;
	}
	srand_curtime();
	port = (unsigned short)rand_natural(65535);
	g_localaddr.sin_family = AF_INET;
	g_localaddr.sin_addr.s_addr = local_addr;
	//g_localaddr.sin_port = htons(48480);
	g_localaddr.sin_port = htons(port);
	DEBUG("eth0  %s : %u \n", inet_ntoa(g_localaddr.sin_addr), port);
	return 0;
}

int tcpscan_sock()
{
	int sock = 0, tmp_int = 0;
	struct timeval tmp_tv;

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if(sock < 0){
		DEBUG("socket: %s \n", strerror(errno));
		return -1;
	}

	tmp_int = 1;
	if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char *)&tmp_int, sizeof(tmp_int)) < 0){
		DEBUG("setsockopt IPPROTO_IP IP_HDRINCL: %s \n", strerror(errno));
		goto ERR;
	}

	tmp_tv.tv_sec = 5;
	tmp_tv.tv_usec = 0;
	if(setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tmp_tv, sizeof(tmp_tv)) < 0){
		DEBUG("setsockopt SOL_SOCKET SO_SNDTIMEO: %s \n", strerror(errno));
		goto ERR;
	}

	tmp_tv.tv_sec = 5;
	if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tmp_tv, sizeof(tmp_tv)) < 0){
		DEBUG("setsockopt SOL_SOCKET SO_RCVTIMEO: %s \n", strerror(errno));
		goto ERR;
	}

	return sock;
ERR:
	if(sock > 0)
		close(sock);
	return -1;
}

int tscan_syn(unsigned int addr, unsigned short port, struct netscan_result *result)
{
	int sock = 0;
#if !MULITITHREAD_NUM
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	struct sockaddr_in rcv_addr;
	int recv_times = 0, on = 0, rst = 0;
	socklen_t sockaddr_len = sizeof(struct sockaddr_in);
#endif
	struct sockaddr_in daddr;
	unsigned char buff[2048] = {0};
	unsigned int buff_len = 0;
	int recv_len;

	//g_localaddr.sin_port = htons((unsigned short)random());
	daddr.sin_family = AF_INET;
	daddr.sin_addr.s_addr = htonl(addr);
	daddr.sin_port = htons(port);
	
	sock = tcpscan_sock();
	if(sock < 0){
		return -1;
	}
//	if( bind(sock, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in)) < 0 ){
//		DEBUG("bind: %s \n", strerror(errno));
//		close(sock);
//		continue;
//	}
	
	buff_len = pack_iptcp_syn(&g_localaddr, &daddr, buff);
	
	recv_len = sendto(sock, buff, buff_len, 0, (struct sockaddr *)&daddr,sizeof(daddr));
	if(recv_len < 0){
		DEBUG("sendto: %s \n", strerror(errno));
		close(sock);
		return -1;
	}
	//NetMsgLog("msg", buff, recv_len, MSG_SEND);
#if !MULITITHREAD_NUM
	recv_times = 0;
	while(recv_times < 3)
	{
		memset(buff, 0, sizeof(buff));
		recv_len = recvfrom(sock, buff, sizeof(buff), 0, (struct sockaddr *)&rcv_addr, &sockaddr_len);
		if(recv_len <= 0){
			DEBUG("recvfrom: %s \n", strerror(errno));
		}
		else{
			//NetMsgLog("msg", buff, recv_len, MSG_RECV);
			iph = (struct iphdr *)&buff[0];
			tcph = (struct tcphdr *)&buff[iph->ihl * 4];
			if(tcph->syn && tcph->ack){
				on = 1;
			}
			else
				rst = 1;
			break;
		}
		++recv_times;
	}

	close(sock);

	printf("%s : %d %s %s \n", inet_ntoa(daddr.sin_addr), ntohs(daddr.sin_port), on ? "on" : "off", rst ? "RST" : "");

	if(result && on == result->type){
		if(save_addr_port(result, addr, port) < 0){
			DEBUG("save_addr_port error \n");
		}
	}
#endif
	return 0;
}

int tscan_syn_listen(void *arg)
{
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	struct sockaddr_in rcv_addr;
	unsigned char buff[2048] = {0};
	int sock = -1, recv_len, on = 0, rst = 0, recv_times = 0;
	socklen_t sockaddr_len = sizeof(struct sockaddr_in);
	struct tcpscan_t *tscan = (struct tcpscan_t *)arg;

	recv_len = netscan_get_targe_num(&tscan->scan);
	recv_times = recv_len + 2;
	do{
		sock = tcpscan_sock();
		if(sock > 0)
			break;
	}while(--recv_len > 0);

	do{
		recv_len = recvfrom(sock, buff, sizeof(buff), 0, (struct sockaddr *)&rcv_addr, &sockaddr_len);
		if(recv_len <= 0){
			DEBUG("recvfrom: %s \n", strerror(errno));
		}
		else{
			//NetMsgLog("msg", buff, recv_len, MSG_RECV);
			iph = (struct iphdr *)&buff[0];
			tcph = (struct tcphdr *)&buff[iph->ihl * 4];
			if(tcph->syn && tcph->ack){
				on = 1;
			}
			else
				rst = 1;
			
			printf("%s : %d %s %s \n", ip_htoa(ntohl(iph->saddr), NULL), ntohs(tcph->source), on ? "on" : "off", rst ? "RST" : "");
			if(tscan->result && on == tscan->result->type){
				if(save_addr_port(tscan->result, ntohl(iph->saddr), ntohs(tcph->source)) < 0){
					DEBUG("save_addr_port error \n");
				}
			}
			on = 0;
			rst = 0;
		}
	}while(--recv_times > 0);

	close(sock);
	return 0;
}

int tscan_connect(unsigned int addr, unsigned short port, struct netscan_result *result)
{
	int sock = -1, on = 0;
	char ip_str[16] = {'\0'};

	sock = wf_tcp_socket(0, 0, NULL);
	if(sock < 0){
		DEBUG("wf_tcp_socket: %s \n", strerror(errno));
		return -1;
	}
	if( wf_connect_addr(sock, htonl(addr), port) < 0){
		DEBUG("wf_connect_addr: %s \n", strerror(errno));
	}
	else{
		on = 1;
	}
	close(sock);

	printf("%s : %d %s \n", ip_htoa(addr, ip_str), (int)port, on ? "on" : "off");

	if(result && on == result->type){
		if(save_addr_port(result, addr, port) < 0){
			DEBUG("save_addr_port error \n");
		}
	}
	return 0;
}

int tscan_proc(void *arg)
{
	struct tscan_task *task = (struct tscan_task *)arg;
	if(!task || !task->tscan)
		return -1;
	if(task->tscan->type == TSCAN_TYPE_CONNECT){
		tscan_connect(task->addr, task->port, task->tscan->result);
	}
	else if(task->tscan->type == TSCAN_TYPE_SYN){
		tscan_syn(task->addr, task->port, task->tscan->result);
	}
	
	free(task);
	return 0;
}

int add_tscan_job(unsigned int addr, unsigned short port, void *tscan)
{
//	int ret = 0;
	struct tscan_task *task = NULL;
	task = (struct tscan_task *)malloc(sizeof(struct tscan_task));
	if(!task){
		return -1;
	}
	task->addr = addr;
	task->port = port;
	task->tscan = (struct tcpscan_t *)tscan;

	if(task->tscan->tdpool){
		if(threadpool_add_job(task->tscan->tdpool, tscan_proc, task, NULL) < 0){
			DEBUG("threadpool_add_job error \n");
			return -1;
		}
	}
	else{
		tscan_proc(task);
	}
	return 0;
}

int tcpscan_done(struct tcpscan_t *tscan)
{
	struct netscan_t *scan = NULL;
	
	if(!tscan)
		return -1;
	
	if(tscan->type == TSCAN_TYPE_SYN){
		if(set_localaddr() < 0)
			return -1;
	}
	
	scan = &tscan->scan;

	return netscan_done(scan, tscan, add_tscan_job);
}

void tcpscan_usage()
{
	fprintf(stderr, "tcpscan usage: \n"
		"tcpscan <-ip ip> <-port port> [-seq ascend\descend\random] [-syn] \n"
		);
}


#if 1
int tcpscan_main(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
{
	int wait_task_num = 0, excu_task_num = 0;
	int syn = 0;
	unsigned long start_time = 0, end_time = 0;
#if MULITITHREAD_NUM
	struct threadpool *tmp_tdpool = NULL;
#endif
	struct arg_parse_t tscan_arg[] = {
		{"-syn", &syn, 0, 0, NULL, ARG_VALUE_TYPE_INT, 1, NULL},
		{NULL, NULL, 0, 0, NULL, 0, 0, NULL}
	};
	int tmp_argc = 0;
	char **tmp_argv = (char **)malloc(sizeof(char *) * argc);

	if(!tmp_argv)
		return 1;

	memset(&g_tscan, 0, sizeof(g_tscan));

	if(netscan_arg_parse(argc, argv, &tmp_argc, tmp_argv, &g_tscan.scan) < 0){
		tcpscan_usage();
		free(tmp_argv);
		return 1;
	}
	netscan_t_print(&g_tscan.scan);
	if(arg_parse(tmp_argc, tmp_argv, tscan_arg, NULL, NULL) < 0){
		tcpscan_usage();
		free(tmp_argv);
		return 1;
	}
	free(tmp_argv);

	get_system_uptime(&start_time);

	if(syn){
		g_tscan.type = TSCAN_TYPE_SYN;
		printf("tcpscan type: tcp syn \n");
	}
	else{
		g_tscan.type = TSCAN_TYPE_CONNECT;
		printf("tcpscan type: socket connect \n");
	}	

	if(netscan_result_init(&g_result, 1) < 0){
		ERROR("init_netscan_result error \n");
		return -1;
	}
	g_tscan.result = &g_result;

#if MULITITHREAD_NUM
	if(g_tscan.type == TSCAN_TYPE_SYN)
		tmp_tdpool = threadpool_init(1, 2);
	else{
		tmp_tdpool = threadpool_init(MULITITHREAD_NUM, 1000);
		g_tscan.tdpool = tmp_tdpool;
	}
	if(!tmp_tdpool){
		ERROR("threadpool_init failed \n");
		goto ERR_END;
	}

	if(g_tscan.type == TSCAN_TYPE_SYN){
		if(threadpool_add_job(tmp_tdpool, tscan_syn_listen, &g_tscan, NULL) < 0){
			DEBUG("threadpool_add_job error \n");
			goto ERR_END;
		}
	}
#endif

	tcpscan_done(&g_tscan);

	if(g_tscan.scan.port){
		free(g_tscan.scan.port);
		g_tscan.scan.port = NULL;
	}
	if(g_tscan.scan.addr){
		free(g_tscan.scan.addr);
		g_tscan.scan.addr = NULL;
	}

#if MULITITHREAD_NUM
	while(1){
		wait_task_num = threadpool_get_waitlist_num(tmp_tdpool);
		excu_task_num = threadpool_get_exculist_num(tmp_tdpool);
		if(!wait_task_num && !excu_task_num)
			break;
		else
			sleep(2);
	}
	threadpool_destroy(tmp_tdpool);
#endif
	
	netscan_result_destory(&g_result, 0);

	get_system_uptime(&end_time);
	printf("[time  %lu s] \n", end_time - start_time);
	return 0;

ERR_END:
	if(tmp_tdpool)
		threadpool_destroy(tmp_tdpool);
	netscan_result_destory(&g_result, 0);
	return 1;
}

