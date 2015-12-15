#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>			// SIOCGIFINDEX
#include <sys/types.h>
#include <netinet/if_ether.h>		// #include <linux/if_arp.h>
#include <netpacket/packet.h>		// struct sockaddr_ll
#include <net/ethernet.h>		// ETH_P_XXX
#include <net/if.h>			// struct ifreq
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <errno.h>

#include "libwf.h"

int sockfd;
unsigned int host_ip;
unsigned char host_mac[6];
unsigned int broad_ip;
unsigned char broad_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
unsigned int gwIp;
unsigned char gwMac[6];
unsigned char recv_buff[4096];

int init_turn_sock()
{
	struct sockaddr_ll sll; // 注意结构体是sockaddr_ll
	struct ifreq ifstruct;
	char ifname[64];

	memset( &sll, 0, sizeof(sll) );
	sll.sll_family = AF_PACKET;

	if( getHostIP_2("eth0", NULL, NULL, ifname, &ifstruct.ifr_ifindex) == 0 )	strcpy(ifstruct.ifr_name, ifname);
	else		strcpy(ifstruct.ifr_name, "eth0");
	
	sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); // 创建Socket
	if(sockfd < 0)
		return -1;

	//ioctl(sockfd, SIOCGIFINDEX, &ifstruct); 
	sll.sll_ifindex = ifstruct.ifr_ifindex;
	sll.sll_protocol = htons(ETH_P_ALL);

	printf("%s %d \n", ifname, ifstruct.ifr_ifindex);

	if(bind(sockfd, (struct sockaddr *) &sll, sizeof(sll)) == -1 ) //在这里当然仍然需要绑定的
	{
		printf("bind error, %s \n", strerror(errno));
		return -1;
	}

	return 0;
}

int turn_init()
{
	char gwip[16], gwmac[24], mac[24], ip[16], broadip[16];

	if( getHostIP("eth0", ip, broadip, NULL) < 0 )
		return -1;
	if( inet_aton(ip, (struct in_addr *)&host_ip) == 0 )
		return -1;
	if( inet_aton(broadip, (struct in_addr *)&broad_ip) == 0 )
		return -1;
	printf("host ip: %s     broad ip: %s \n", ip, broadip);
	
	if( getMAC_byCmd(mac) == 0 )
		return -1;
	str2mac(mac, host_mac);
	printf("host mac: %s \n", mac);
		
	if( getGWMAC_byCmd(gwip, gwmac) <= 0 )
		return -1;
	if( inet_aton(gwip, (struct in_addr *)&gwIp) == 0 )
		return -1;
	str2mac(gwmac, gwMac);
	printf("gw ip: %s  gw mac: %s  \n", gwip, gwmac);

	if( init_turn_sock() < 0 )
		return -1;
}

void turn()
{
	int len=0, recv_len=0, ret=0;
	unsigned char *macDst = NULL, *macSrc = NULL;
	unsigned short proto;
	struct ethhdr *eth;
	unsigned char *buf;
	struct iphdr *iph;
	
	memset(recv_buff, 0, sizeof(recv_buff));
	len = recv(sockfd, recv_buff, sizeof(recv_buff), 0);

	if(len > 0)
	{
		macDst = recv_buff;
		macSrc = macDst + 6;
		buf = recv_buff;
		recv_len = len;
	
		if(len < sizeof(struct ethhdr))
			return;
		eth = (struct ethhdr *)buf;
		proto = ntohs(eth->h_proto);

		if( memcmp(macSrc, host_mac, 6) == 0 )
			return;
		if( memcmp(macDst, broad_mac, 6) == 0 )
			return;
		if(proto == ETH_P_IP)
		{
			buf = buf+sizeof(struct ethhdr);
			len = len-sizeof(struct ethhdr);

			if(len < sizeof(struct iphdr))	
				return;
			iph = (struct iphdr *)buf;

			if( iph->daddr == broad_ip )
				return;
			if( iph->saddr == host_ip )
				return;
			if( iph->daddr != host_ip )
			{
				//NetMsgLog("data", recv_buff, recv_len, MSG_NO);
				memcpy(macDst, gwMac, 6);
				ret = send(sockfd, recv_buff, recv_len, 0);
				//printf("ret of send: %d,  %s \n", ret, strerror(errno));
				//NetMsgLog("data", recv_buff, recv_len, MSG_NO);
			}
		}
	}
}

void turn_exit_system()
{
	close(sockfd);
	exit(0);
}

int main(int argc, char **argv)
{

	if( turn_init() < 0)
		exit_error("init failed");

	wf_damen(turn_exit_system);

	while(1)
	{
		turn();
	}

	turn_exit_system();
	return 0;
}
