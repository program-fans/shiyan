#ifndef NET_PACKET_H_
#define NET_PACKET_H_

#include <sys/socket.h>
#include <sys/ioctl.h>			// SIOCGIFINDEX
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>		// #include <linux/if_arp.h>
#include <netpacket/packet.h>		// struct sockaddr_ll
#include <net/ethernet.h>		// ETH_P_XXX
#include <net/if.h>			// struct ifreq
//#include <linux/in.h>			// conflict with <netinet/in.h>
#include <linux/udp.h>	
#include <linux/tcp.h>	
#include <netinet/ip_icmp.h>


extern unsigned short complement_checksum(unsigned short *buff, unsigned int size);
extern unsigned short ip_checksum(struct iphdr *iph, unsigned char *option, unsigned int opt_len);


#define TCPOPT_NOP		1
#define TCPOPT_MSS		2
#define TCPOPT_WS		3
#define TCPOPT_SACK		4
#define TCPOPT_TSVAL	8
#define TCPOPT_PADD	255

struct tcp_option
{
	unsigned long option;
	unsigned int len;
	unsigned char buff[40];
};

extern int tcp_set_option(struct tcp_option *opt, int option, void *arga, void *argb);

struct fake_tcpudphdr
{
	unsigned int saddr;
	unsigned int daddr;
	unsigned char pad;
	unsigned char protocol;
	unsigned short len;
};

extern unsigned short tcp_checksum(struct fake_tcpudphdr *fake_tcph, struct tcphdr *tcph, struct tcp_option *topt);
extern unsigned int pack_iptcp_syn_option(struct sockaddr_in *saddr, struct sockaddr_in *daddr, unsigned char *buff);
extern unsigned int pack_iptcp_syn(struct sockaddr_in *saddr, struct sockaddr_in *daddr, unsigned char *buff);

#endif

