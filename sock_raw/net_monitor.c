#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>

#include "libwf.h"

#include "net_monitor.h"
#include "http.h"
#include "filter.h"

struct globle_set
{
	int log_close;
	int filter_close;
	int peek_close;
	int call_close;
};

#define CALLPATH			"/home/net_monitor_ipc"
#define LOGPATH				"./log/"
#define LOGMSG_FILE_NAME	"msg"

int call_sock;
int sockfd;
unsigned char monitor_buff[4096];
char log_buf[1024];
struct globle_set g_set;
char callpath[256];
unsigned int packets = 0, pkt_filte = 0;

void unpack_icmp(unsigned char *buf, int len)
{
	return;
}
void unpack_tcp(unsigned char *buf, int len)
{
	unsigned char *data = NULL;
	int hlen=0, data_len = 0;
	struct tcphdr *tcph;
	unsigned short s_port, d_port;
	
	if(len < sizeof(struct tcphdr))	return;
	tcph = (struct tcphdr *)buf;
	hlen = (int)(tcph->doff * 4);
	data_len = len - hlen;
	if(data_len > 0)	data = buf + hlen;
	s_port = ntohs(tcph->source);
	d_port = ntohs(tcph->dest);

	NetMsgLogNote(LOGMSG_FILE_NAME, MSG_NO, ">>> Tcp header\nSource port: %u  Dest port: %u", s_port, d_port);
	NetMsgLogNote(LOGMSG_FILE_NAME, MSG_NO, "Head length: %d(*4)", tcph->doff);
	NetMsgLogNote(LOGMSG_FILE_NAME, MSG_NO, "URG: %s", tcph->urg ? "set" : "not set");
	NetMsgLogNote(LOGMSG_FILE_NAME, MSG_NO, "ACK: %s", tcph->ack ? "set" : "not set");
	NetMsgLogNote(LOGMSG_FILE_NAME, MSG_NO, "PSH: %s", tcph->psh ? "set" : "not set");
	NetMsgLogNote(LOGMSG_FILE_NAME, MSG_NO, "RST: %s", tcph->rst ? "set" : "not set");
	NetMsgLogNote(LOGMSG_FILE_NAME, MSG_NO, "SYN: %s", tcph->syn ? "set" : "not set");
	NetMsgLogNote(LOGMSG_FILE_NAME, MSG_NO, "FIN: %s", tcph->fin ? "set" : "not set");

	NetMsgLogNote(LOGMSG_FILE_NAME, MSG_NO, "Data: (%d)%s", data_len>0 ? data_len : 0, data ? " " : "no data");
	if(data)
	{
		wf_msglog(LOGMSG_FILE_NAME, 0, 1, data, data_len);
		//wf_msglog(LOGMSG_FILE_NAME, 0, 0, data, data_len);
	}
	
	return;
}
void unpack_udp(unsigned char *buf, int len)
{
	unsigned short dlen=0;
	int data_len=0;
	unsigned char *data = NULL;
	struct udphdr *udph;
	
	if(len < sizeof(struct udphdr))	return;
	udph = (struct udphdr *)buf;
	dlen = ntohs(udph->len);
	data_len = (int)dlen - sizeof(struct udphdr);
	if(data_len > 0)	data = buf + sizeof(struct udphdr);

	NetMsgLogNote(LOGMSG_FILE_NAME, MSG_NO,">>> Udp header\nSource port: %u  Dest port: %u", ntohs(udph->source), ntohs(udph->dest));
	NetMsgLogNote(LOGMSG_FILE_NAME, MSG_NO, "Data length: %u(-8)", dlen);

	NetMsgLogNote(LOGMSG_FILE_NAME, MSG_NO, "Data: (%d)%s", data_len>0 ? data_len : 0, data ? " " : "no data");
	if(data)
	{
		wf_msglog(LOGMSG_FILE_NAME, 0, 1, data, data_len);
		//wf_msglog(LOGMSG_FILE_NAME, 0, 0, data, data_len);
	}
}
void unpack_ip(unsigned char *buf, int len)
{
	unsigned int head_len;
	struct iphdr *iph;

	if(len < sizeof(struct iphdr))	return;
	iph = (struct iphdr *)buf;

	NetMsgLogNote(LOGMSG_FILE_NAME, MSG_NO, ">>> IP header\nVersion: %u, Head length: %u(*4)", iph->version, iph->ihl);
	NetMsgLogNote(LOGMSG_FILE_NAME, MSG_NO, "Total length: %u  TTL: %u", ntohs(iph->tot_len), iph->ttl);
	NetMsgLogNote(LOGMSG_FILE_NAME, MSG_NO, "Proto type: %s(0x%02X %d)", get_ip_proto_str(iph->protocol), iph->protocol, iph->protocol);
	//NetMsgLogNote(LOGMSG_FILE_NAME, MSG_NO,"Source ip: %s  Dest ip: %s", inet_ntoa(iph->saddr), inet_ntoa(iph->daddr));
	// error: first inet_ntoa == second inet_ntoa
	NetMsgLogNote(LOGMSG_FILE_NAME, MSG_NO,"Source ip: %s", inet_ntoa(iph->saddr));
	NetMsgLogNote(LOGMSG_FILE_NAME, MSG_NO,"Dest ip: %s", inet_ntoa(iph->daddr));

	head_len = iph->ihl * 4;
	switch(iph->protocol)
	{
	case IPPROTO_ICMP: unpack_icmp(buf+head_len, len-head_len);
		break;
	case IPPROTO_TCP: unpack_tcp(buf+head_len, len-head_len);
		break;
	case IPPROTO_UDP: unpack_udp(buf+head_len, len-head_len);
		break;
	default:
		break;
	}
}
void unpack_arp(unsigned char *buf, int len)
{
	unsigned short hrd, pro;
	struct arphdr *arph;
	unsigned char *data, *data2;
	unsigned int *ip;

	if(len < sizeof(struct arphdr))	return;
	arph = (struct arphdr *)buf;

	hrd = ntohs(arph->ar_hrd);
	pro = ntohs(arph->ar_pro);
	NetMsgLogNote(LOGMSG_FILE_NAME, MSG_NO, ">>> ARP header\nHardware type: %s(%04X)  Proto type: %s(%04X)", 
		get_hrdtype_str(hrd), hrd, get_proto_str(pro), pro);

	NetMsgLogNote(LOGMSG_FILE_NAME, MSG_NO, "Length of hardware address: %u  length of protocol address: %u \nOp code: %s", 
		arph->ar_hln, arph->ar_pln, get_arpOpCode_str(ntohs(arph->ar_op)));

	data = buf+sizeof(struct arphdr);
	data2 = data + 6;
	ip = (unsigned int *)data2;
	NetMsgLogNote(LOGMSG_FILE_NAME, MSG_NO, "MAC of sender: "MAC_FORMAT_STRING"\nIp of sender: %s", 
		MAC_FORMAT_SPLIT(data), inet_ntoa(*ip));

	data = data2 + 4;
	data2 = data + 6;
	ip = (unsigned int *)data2;
	NetMsgLogNote(LOGMSG_FILE_NAME, MSG_NO, "MAC of target: "MAC_FORMAT_STRING"\nIp of target: %s", 
		MAC_FORMAT_SPLIT(data), inet_ntoa(*ip));
}

void unpack_mac(unsigned char *buf, int len)
{
	unsigned short proto;
	struct ethhdr *eth;

	if(len < sizeof(struct ethhdr))	return;
	eth = (struct ethhdr *)buf;
	proto = ntohs(eth->h_proto);

	//NetMsgLogNote(LOGMSG_FILE_NAME, MSG_NO, "----------------------");
	NetMsgLogNote(LOGMSG_FILE_NAME, MSG_NO, ">>> MAC header\nDest MAC: "MAC_FORMAT_STRING"\nSource MAC: "MAC_FORMAT_STRING, 
		MAC_FORMAT_SPLIT(eth->h_dest),
		MAC_FORMAT_SPLIT(eth->h_source));
	NetMsgLogNote(LOGMSG_FILE_NAME, MSG_NO, "Proto: %s(%04X)", get_proto_str(proto), proto);
	
	switch(proto)
	{
	case ETH_P_IP: unpack_ip(buf+sizeof(struct ethhdr), len-sizeof(struct ethhdr));
		break;
 	case ETH_P_ARP: unpack_arp(buf+sizeof(struct ethhdr), len-sizeof(struct ethhdr));
		break;
	defult:
		break;
	}
}

int monitor()
{
	int len=0;
	
	memset(monitor_buff, 0, sizeof(monitor_buff));
	len = recv(sockfd, monitor_buff, sizeof(monitor_buff), 0);

	if(len > 0)
	{
		++packets;
		if( filter(monitor_buff, len) == FILTER_DROP ){
			++pkt_filte;
			return len;
		}
		
		peek(monitor_buff, len);

		if(g_set.log_close)
			return len;
		NetMsgLog(LOGMSG_FILE_NAME, monitor_buff, len, MSG_NO);
		//NetMsgLogAsc(LOGMSG_FILE_NAME, monitor_buff, 0, MSG_NO);
		unpack_mac(monitor_buff, len);
	}

	return len;
}

int response_call(char *cmd, char *result)
{
	if(cmd == NULL || result == NULL)
		return -1;

	printf("call: %s \n", cmd);
	sprintf(result, "%s", "success");

	return 0;
}
int net_monitor_call(int msg, unsigned long pa, unsigned long pb, unsigned long pc, unsigned long pd)
{
	return response_call((char *)pa, (char *)pb);
}

int init()
{
	struct sockaddr_ll sll; // 注意结构体是sockaddr_ll
	struct ifreq ifstruct;
	char ifname[64];

	memset( &sll, 0, sizeof(sll) );
	sll.sll_family = AF_PACKET;

	if( getHostIP_2("eth0", NULL, NULL, ifname, &ifstruct.ifr_ifindex) == 0 )	strcpy(ifstruct.ifr_name, ifname);
	else		strcpy(ifstruct.ifr_name, "eth0");

	sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); // 创建Socket

	//ioctl(sockfd, SIOCGIFINDEX, &ifstruct); //控制I/O设备
	sll.sll_ifindex = ifstruct.ifr_ifindex;
	sll.sll_protocol = htons(ETH_P_ALL);
/*
	if(bind(sockfd, (struct sockaddr *) &sll, sizeof(sll)) == -1 ) //在这里当然仍然需要绑定的
	{
		printf("bind error \n");
		return -1;
	}
*/
	return 0;
}

void deal_arg(int argc, char **argv)
{
	int i=0, size = 0, argc_start=1;
	char *str = NULL;
	FILE *rule_file = NULL;
	char rule_buf[128] = {'\0'};
	char rule_str[128] = {'\0'};
	
	
	if(argc < (argc_start+1))
		return;
	if(strcmp(argv[argc_start], "-close") == 0)
	{
		if(argc < (argc_start+2))
			exit_error("set error");
		str = argv[argc_start+1];
		size = strlen(str);
		for(i=0; i<size; i++)
		{
			if( str[i] == 'p' )
				g_set.peek_close = 1;
			if( str[i] == 'f' )
				g_set.filter_close = 1;
			if( str[i] == 'l' )
				g_set.log_close = 1;
		}
		argc_start = 3;
	}

	if(g_set.filter_close)
		return;
	if(argc < (argc_start+1))
		return;
// read rule file	
	if(strcmp(argv[argc_start], "-f") == 0)
	{
		if(argc < (argc_start+2))
			exit_error(ERROR_STR_FILTER_RULE);
		rule_file = fopen(argv[argc_start+1],"r");
		if( rule_file == NULL)
			exit_error("rule file open failed");

		while( fgets(rule_buf,sizeof(rule_buf),rule_file) != NULL  )
		{
			if(rule_buf[0] == '#')
				continue;
			
			wipe_off_CRLF_inEnd(rule_buf);
			wipe_off_blank(rule_buf, rule_str, sizeof(rule_str));

			if( rule_str_parse(rule_str) < 0 )
			{
				rule_close();
				exit_error(ERROR_STR_FILTER_RULE);
			}
			
			memset(rule_buf, 0, sizeof(rule_buf));
		}
		fclose(rule_file);
		goto ENABLE_FILTER;
	}
// read rule param
	if( ((argc-argc_start) % 3) != 0 )
		exit_error(ERROR_STR_FILTER_RULE);
	
	for(i=argc_start; i<argc; i+=3)
	{
		size = strlen(argv[i]) + strlen(argv[i+1]) + strlen(argv[i+2]);
		str = (char *)malloc(size+1);
		if(str == NULL)
		{
			rule_close();
			exit_error(ERROR_STR_MALLOC);
		}
		
		strcpy(str, argv[i]);
		strcat(str, argv[i+1]);
		strcat(str, argv[i+2]);
		
		if( rule_str_parse(str) < 0 )
		{
			wf_free(str);
			rule_close();
			exit_error(ERROR_STR_FILTER_RULE);
		}
		
		wf_free(str);
	}

ENABLE_FILTER:
	rule_enable();
	print_rule();
}



void nm_exit_system()
{
	peek_close();
	rule_close();
	close(sockfd);
	ipc_server_close(CALLPATH, call_sock);
	printf("\n  packets: %u  filte: %u    [%u] \n", packets, pkt_filte, packets-pkt_filte);
	pprint("exit...[log=> %s] \n", LOGPATH);

	exit(0);
}
int main(int argc, char **argv)
{
	long last=0, now=0;
	int max_fd;
	fd_set fds;
	struct timeval tv;
	
	signal(SIGINT, nm_exit_system);/*register signal handler #include <signal.h>*/
	signal(SIGTERM, nm_exit_system);/*register signal handler*/
	signal(SIGKILL, nm_exit_system);/*register signal handler*/

	g_set.peek_close = 0;
	g_set.filter_close = 0;
	g_set.log_close = 0;
	g_set.call_close = 0;

	call_sock = ipc_server_init(CALLPATH, net_monitor_call);
	if(call_sock < 0)
	{
		printf("ipc init failed, close it \n");
		g_set.call_close = 1;
	}
		
	rule_init();
	peek_init();
	deal_arg(argc, argv);
	if(g_set.filter_close)
		rule_disEnable();
	if(!g_set.peek_close)
	{
		if( read_match("zmatch.txt") < 0)
			printf("read_match failed, set it invaild \n");
		//else
			//print_matchlist();
		peek_enable();
	}
	
	wf_set_logcfg(LOGPATH, NULL, LOG_ALL, SPLIT_OFF);
	if( init()<0 )	return -1;

	while(g_set.call_close)
	{
		now = get_system_uptime(NULL);
		peek_loop_1(now);
		peek_loop_2(now);
		monitor();
	}

	while(!g_set.call_close)
	{
		now = get_system_uptime(NULL);
		peek_loop_1(now);
		peek_loop_2(now);
	
		tv.tv_sec = 0;
		tv.tv_usec = 100000;		// 100 * 1000   100ms
		FD_ZERO(&fds);
		WF_FD_SET(sockfd, &fds, max_fd);
		WF_FD_SET(call_sock, &fds, max_fd);
		if(select(max_fd+1, &fds, NULL, NULL, &tv) < 0)
		{
			if(errno == EINTR || errno == EAGAIN)
				continue;
		}

		if( FD_ISSET(sockfd, &fds) )
			monitor();
		if( FD_ISSET(call_sock, &fds) )
			ipc_server_accept(call_sock);
	}

	nm_exit_system();
	return 0;
}

