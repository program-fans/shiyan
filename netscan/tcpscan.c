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

	tmp_tv.tv_sec = 1;
	tmp_tv.tv_usec = 0;
	if(setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tmp_tv, sizeof(tmp_tv)) < 0){
		DEBUG("setsockopt SOL_SOCKET SO_SNDTIMEO: %s \n", strerror(errno));
		goto ERR;
	}

	tmp_tv.tv_sec = 1;
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
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	struct sockaddr_in daddr, rcv_addr;
	unsigned char buff[2048] = {0};
	unsigned int buff_len = 0;
	int recv_len, recv_times = 0, on = 0, rst = 0;
	socklen_t sockaddr_len = sizeof(struct sockaddr_in);

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
	
	return 0;
}

int tscan_connect(unsigned int addr, unsigned short port, struct netscan_result *result)
{
	int sock = -1, on = 0;
	char ip_str[16] = {'\0'};

	sock = wf_tcp_socket(0, 0);
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
	if(!netscan_check(&tscan->scan)){
		ERROR("netscan invalid \n");
		return -1;
	}
	if(tscan->type == TSCAN_TYPE_SYN){
		if(set_localaddr() < 0)
			return -1;
	}
	
	scan = &tscan->scan;

	return  netscan_done(scan, tscan, add_tscan_job);
}


#define MULITITHREAD_NUM			15
int main(int argc, char **argv)
{
	int i=-1, syn = 1, wait_task_num = 0, excu_task_num = 0;
	unsigned long start_time = 0, end_time = 0;
	
	get_system_uptime(&start_time);

	memset(&g_tscan, 0, sizeof(g_tscan));
	ip_atoh("192.168.0.1", &g_tscan.scan.saddr);
	ip_atoh("192.168.0.2", &g_tscan.scan.eaddr);
	//ip_atoh("192.168.0.3", &g_tscan.scan.eaddr);
	set_bit(SCAN_FLAG_ADDR_CONTINUE, &g_tscan.scan.flags);
	g_tscan.scan.port = (unsigned short *)malloc(sizeof(unsigned short) * 6);
	if(!g_tscan.scan.port){
		return -1;
	}
	g_tscan.scan.port[++i] = 80;
	g_tscan.scan.port[++i] = 83;
	g_tscan.scan.port[++i] = 49152;
	g_tscan.scan.port[++i] = 49153;
	g_tscan.scan.port[++i] = 49154;
	g_tscan.scan.port[++i] = 49155;
	g_tscan.scan.port_num = 6;
	set_bit(SCAN_FLAG_PORT_DISCONTINUE, &g_tscan.scan.flags);

	if(netscan_port_random(&g_tscan.scan) < 0){
		ERROR("netscan_port_random error \n");
		return -1;
	}

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

	if(MULITITHREAD_NUM){
		g_tscan.tdpool = threadpool_init(MULITITHREAD_NUM, 1000);
		if(!g_tscan.tdpool){
			ERROR("threadpool_init failed \n");
			return -1;
		}
	}

	tcpscan_done(&g_tscan);

	if(g_tscan.scan.port){
		free(g_tscan.scan.port);
		g_tscan.scan.port = NULL;
	}
	if(g_tscan.scan.addr){
		free(g_tscan.scan.addr);
		g_tscan.scan.addr = NULL;
	}

	if(MULITITHREAD_NUM){
		while(1){
			wait_task_num = threadpool_get_waitlist_num(g_tscan.tdpool);
			excu_task_num = threadpool_get_exculist_num(g_tscan.tdpool);
			if(!wait_task_num && !excu_task_num)
				break;
			else
				sleep(2);
		}

		threadpool_destroy(g_tscan.tdpool);
	}
	
	netscan_result_destory(&g_result, 0);

	get_system_uptime(&end_time);
	printf("[time  %lu s] \n", end_time - start_time);
	return 0;
}

