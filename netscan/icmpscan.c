#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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


struct icmpscan_t
{
	struct netscan_t scan;
	struct netscan_result *result;
	int send_sock;
	int recv_sock;
	pid_t child;
};

static int icmp_send_proc(unsigned int addr, unsigned short port, void *icmpscan)
{
	struct icmpscan_t *icmp_scan = (struct icmpscan_t *)icmpscan;
	struct sockaddr_in addr_to;
	
//	DEBUG("sendsock: %d  addr: %x \n", icmp_scan->send_sock, addr);
	memset(&addr_to, 0, sizeof(addr_to));
	addr_to.sin_addr.s_addr = htonl(addr);
	addr_to.sin_family =AF_INET;

	return icmp_send_echo(icmp_scan->send_sock, 1, &addr_to);
}

int icmpscan_done(struct icmpscan_t *icmpscan)
{
	struct netscan_t *scan = NULL;
	int ret = 0;
	
	if(!icmpscan)
		return -1;

	icmpscan->send_sock = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
	if(icmpscan->send_sock < 0){
		perror("socket error");
		return icmpscan->send_sock;
	}
	
	scan = &icmpscan->scan;
	ret = netscan_done(scan, icmpscan, icmp_send_proc);
	if(ret < 0){
		ERROR("netscan is invalid \n");
	}

	close(icmpscan->send_sock);
	icmpscan->send_sock = 0;
	return ret;
}

static int icmpscan_read_icmp(int sock, struct icmpscan_t *icmpscan)
{
	int len = 0;
	unsigned char buff[2048] = {0};
	struct icmphdr *icmph = NULL;
	struct iphdr *iph = NULL;
	struct in_addr addr;
	char os_type[24] = {'\0'};

	len = recvfrom(sock, buff, sizeof(buff), 0, NULL, NULL);
	if( len <0 ){
		perror("icmp recvfrom error");
		return len;
	}

	iph = (struct iphdr *)(&buff[0]);
	if(iph->protocol != IPPROTO_ICMP)
		return 0;
//	DEBUG("recv icmp %x \n", iph->saddr);
	
	icmph = (struct icmphdr *)((char *)iph + (iph->ihl << 2));
	if(icmph->type == ICMP_ECHOREPLY){
		if(icmpscan->result)
			save_addr_port(icmpscan->result, ntohl(iph->daddr), 0);

		ttl_2_os_type(iph->ttl, os_type, sizeof(os_type));
		addr.s_addr = iph->saddr;
		printf("%s  %s  [on] \n", inet_ntoa(addr), os_type);
	}

	return 0;
}

static int icmpscan_recv_proc(struct icmpscan_t *icmpscan)
{
	int icmp_sock = -1;
	int max_fd = 0, ret = 0;
	fd_set fds;
	struct timeval tv;
	int set_tv = 0;
	
	icmp_sock = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
	if(icmp_sock < 0){
		perror("socket error");
		return icmp_sock;
	}

	while(1)
	{
		if(set_tv){
			tv.tv_sec = 2;
			tv.tv_usec = 0;
		}
		else{
			tv.tv_sec = 1;
			tv.tv_usec = 0;
		}
		FD_ZERO(&fds);
		WF_FD_SET(icmp_sock, &fds, max_fd);

		ret = select(max_fd+1, &fds, NULL, NULL, &tv);
		if(ret < 0)
		{
			if(errno == EINTR || errno == EAGAIN)
				continue;
		}
		else if(ret > 0){
			if( FD_ISSET(icmp_sock, &fds) )
				icmpscan_read_icmp(icmp_sock, icmpscan);
		}
		else{
			if(set_tv)
				break;
			if(waitpid_sec(icmpscan->child, NULL, 1) < 1)
				set_tv = 1;
		}
	}
	close(icmp_sock);

	return 0;
}


struct icmpscan_t g_icmpscan;
struct netscan_result g_result;
int main(int argc, char **argv)
{
//	int i=-1;
	unsigned long start_time = 0, end_time = 0;
	pid_t child = 0;
	
	get_system_uptime(&start_time);

	memset(&g_icmpscan, 0, sizeof(g_icmpscan));
	ip_atoh("192.168.0.1", &g_icmpscan.scan.saddr);
	ip_atoh("192.168.0.8", &g_icmpscan.scan.eaddr);
	set_bit(SCAN_FLAG_ADDR_CONTINUE, &g_icmpscan.scan.flags);
#if 0
	if(netscan_addr_random(&g_icmpscan.scan) < 0){
		ERROR("netscan_addr_random error \n");
		return -1;
	}
#else
	set_bit(SCAN_FLAG_ASCEND, &g_icmpscan.scan.flags);
#endif
	child = fork();
	if(child == 0){
		sleep(1);			// let parent run at first
		icmpscan_done(&g_icmpscan);

		if(g_icmpscan.scan.addr){
			free(g_icmpscan.scan.addr);
			g_icmpscan.scan.addr = NULL;
		}
		DEBUG("child send finish and exit \n");
		exit(0);
	}
	else if(child < 0){
		ERROR("fork failed \n");
		return -1;
	}

	if(netscan_result_init(&g_result, 1) < 0){
		ERROR("init_netscan_result error \n");
		return -1;
	}
	g_icmpscan.result = &g_result;

	g_icmpscan.child = child;
	icmpscan_recv_proc(&g_icmpscan);

	if(g_icmpscan.scan.addr){
		free(g_icmpscan.scan.addr);
		g_icmpscan.scan.addr = NULL;
	}

	netscan_result_destory(&g_result, 0);

	get_system_uptime(&end_time);
	printf("[time  %lu s] \n", end_time - start_time);
	return 0;

}

