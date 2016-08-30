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


struct udpscan_t
{
	struct netscan_t scan;
	struct netscan_result *result;
	pid_t child;
};


static int uscan_proc(unsigned int addr, unsigned short port, void *uscan)
{
	int sock = -1;
	unsigned char buf[16];
	struct sockaddr_in addr_to;
	
	sock = wf_udp_socket(0, 0, NULL);
	if(sock < 0){
		return -1;
	}

	memset(&addr_to, 0, sizeof(addr_to));
	addr_to.sin_addr.s_addr = htonl(addr);
	addr_to.sin_family =AF_INET;
	addr_to.sin_port = htons(port);

	wf_sendto(sock, buf, sizeof(buf), 0, &addr_to);
	close(sock);
	return 0;
}

int udpscan_done(struct udpscan_t *uscan)
{
	struct netscan_t *scan = NULL;
	
	if(!uscan)
		return -1;
	
	scan = &uscan->scan;

	return  netscan_done(scan, uscan, uscan_proc);
}

static int uscan_read_icmp(int sock, struct udpscan_t *uscan)
{
	int len = 0;
	unsigned char buff[2048] = {0};
	struct icmphdr *icmph = NULL;
	struct iphdr *iph = NULL;
	unsigned short *dport = NULL;
	struct in_addr addr;

	len = recvfrom(sock, buff, sizeof(buff), 0, NULL, NULL);
	if( len <0 ){
		perror("icmp recvfrom error");
		return len;
	}

	iph = (struct iphdr *)(&buff[0]);
	if(iph->protocol != IPPROTO_ICMP)
		return 0;
	
	icmph = (struct icmphdr *)((char *)iph + (iph->ihl << 2));
	if(icmph->type != ICMP_DEST_UNREACH){
		return 0;
	}
	
	if(icmph->code == ICMP_PORT_UNREACH || icmph->code == ICMP_HOST_UNREACH){
		iph = (struct iphdr *)((char *)icmph + sizeof(struct icmphdr));
		dport = (unsigned short *)((char *)iph + (iph->ihl << 2) + 2);
		if(uscan->result)
			save_addr_port(uscan->result, ntohl(iph->daddr), ntohs(*dport));

		addr.s_addr = iph->daddr;
		printf("%s : %u  off \n", inet_ntoa(addr), ntohs(*dport));
	}

	return 0;
}

static int uscan_icmp_proc(struct udpscan_t *uscan)
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
				uscan_read_icmp(icmp_sock, uscan);
		}
		else{
			if(set_tv)
				break;
			if(waitpid_sec(uscan->child, NULL, 1) < 1)
				set_tv = 1;
		}
	}
	close(icmp_sock);

	return 0;
}


struct udpscan_t g_uscan;
struct netscan_result g_result;
int main(int argc, char **argv)
{
	int i=-1;
	unsigned long start_time = 0, end_time = 0;
	pid_t child = 0;
	
	get_system_uptime(&start_time);

	memset(&g_uscan, 0, sizeof(g_uscan));
	ip_atoh("192.168.0.1", &g_uscan.scan.saddr);
	ip_atoh("192.168.0.2", &g_uscan.scan.eaddr);
	//ip_atoh("192.168.0.3", &g_tscan.scan.eaddr);
	set_bit(SCAN_FLAG_ADDR_CONTINUE, &g_uscan.scan.flags);
	g_uscan.scan.port = (unsigned short *)malloc(sizeof(unsigned short) * 6);
	if(!g_uscan.scan.port){
		return -1;
	}
	g_uscan.scan.port[++i] = 80;
	g_uscan.scan.port[++i] = 83;
	g_uscan.scan.port[++i] = 49152;
	g_uscan.scan.port[++i] = 49153;
	g_uscan.scan.port[++i] = 49154;
	g_uscan.scan.port[++i] = 49155;
	g_uscan.scan.port_num = 6;
	set_bit(SCAN_FLAG_PORT_DISCONTINUE, &g_uscan.scan.flags);

	if(netscan_port_random(&g_uscan.scan) < 0){
		ERROR("netscan_port_random error \n");
		return -1;
	}

	child = fork();
	if(child == 0){
		sleep(1);			// let parent run at first
		udpscan_done(&g_uscan);
		if(g_uscan.scan.port){
			DEBUG("free port \n");
			free(g_uscan.scan.port);
			g_uscan.scan.port = NULL;
		}
		if(g_uscan.scan.addr){
			free(g_uscan.scan.addr);
			g_uscan.scan.addr = NULL;
		}
		DEBUG("child finish and exit \n");
		exit(0);
	}
	else if(child < 0){
		ERROR("fork failed \n");
		return -1;
	}

	if(netscan_result_init(&g_result, 0) < 0){
		ERROR("init_netscan_result error \n");
		return -1;
	}
	g_uscan.result = &g_result;

	g_uscan.child = child;
	uscan_icmp_proc(&g_uscan);

	if(g_uscan.scan.port){
		DEBUG("free port \n");
		free(g_uscan.scan.port);
		g_uscan.scan.port = NULL;
	}
	if(g_uscan.scan.addr){
		free(g_uscan.scan.addr);
		g_uscan.scan.addr = NULL;
	}

	netscan_result_destory(&g_result, 0);

	get_system_uptime(&end_time);
	printf("[time  %lu s] \n", end_time - start_time);
	return 0;

}

