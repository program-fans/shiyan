#ifndef NET_STR_H_
#define NET_STR_H_

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

#include "http.h"

#define OTHER_STR	" "

// proto type str
//#define ETH_P_LOOP	0x0060		/* Ethernet Loopback packet	*/
//#define ETH_P_PUP	0x0200		/* Xerox PUP packet		*/
//#define ETH_P_PUPAT	0x0201		/* Xerox PUP Addr Trans packet	*/
#define ETH_P_IP_STR	"IP"		/* Internet Protocol packet	*/
//#define ETH_P_X25	0x0805		/* CCITT X.25			*/
#define ETH_P_ARP_STR	"ARP"		/* Address Resolution packet	*/
//#define	ETH_P_BPQ	0x08FF		/* G8BPQ AX.25 Ethernet Packet	[ NOT AN OFFICIALLY REGISTERED ID ] */
//#define ETH_P_IEEEPUP	0x0a00		/* Xerox IEEE802.3 PUP packet */
//#define ETH_P_IEEEPUPAT	0x0a01		/* Xerox IEEE802.3 PUP Addr Trans packet */
//#define ETH_P_DEC       0x6000          /* DEC Assigned proto           */
//#define ETH_P_DNA_DL    0x6001          /* DEC DNA Dump/Load            */
//#define ETH_P_DNA_RC    0x6002          /* DEC DNA Remote Console       */
//#define ETH_P_DNA_RT    0x6003          /* DEC DNA Routing              */
//#define ETH_P_LAT       0x6004          /* DEC LAT                      */
//#define ETH_P_DIAG      0x6005          /* DEC Diagnostics              */
//#define ETH_P_CUST      0x6006          /* DEC Customer use             */
//define ETH_P_SCA       0x6007          /* DEC Systems Comms Arch       */
//#define ETH_P_TEB	0x6558		/* Trans Ether Bridging		*/
//#define ETH_P_RARP      0x8035		/* Reverse Addr Res packet	*/
//#define ETH_P_ATALK	0x809B		/* Appletalk DDP		*/
#define ETH_P_AARP_STR	"AARP"		/* Appletalk AARP		*/
//#define ETH_P_8021Q	0x8100          /* 802.1Q VLAN Extended Header  */
//#define ETH_P_IPX	0x8137		/* IPX over DIX			*/
#define ETH_P_IPV6_STR	"IPV6"		/* IPv6 over bluebook		*/
//#define ETH_P_PAUSE	0x8808		/* IEEE Pause frames. See 802.3 31B */
//#define ETH_P_SLOW	0x8809		/* Slow Protocol. See 802.3ad 43B */
//#define ETH_P_WCCP	0x883E		/* Web-cache coordination protocol* defined in draft-wilson-wrec-wccp-v2-00.txt */
//#define ETH_P_PPP_DISC	0x8863		/* PPPoE discovery messages     */
//#define ETH_P_PPP_SES	0x8864		/* PPPoE session messages	*/
//#define ETH_P_MPLS_UC	0x8847		/* MPLS Unicast traffic		*/
//#define ETH_P_MPLS_MC	0x8848		/* MPLS Multicast traffic	*/
//#define ETH_P_ATMMPOA	0x884c		/* MultiProtocol Over ATM	*/
//#define ETH_P_LINK_CTL	0x886c		/* HPNA, wlan link local tunnel */
//#define ETH_P_ATMFATE	0x8884		/* Frame-based ATM Transport
					 // over Ethernet
//#define ETH_P_PAE	0x888E		/* Port Access Entity (IEEE 802.1X) */
//#define ETH_P_AOE	0x88A2		/* ATA over Ethernet		*/
//#define ETH_P_TIPC	0x88CA		/* TIPC 			*/
//#define ETH_P_1588	0x88F7		/* IEEE 1588 Timesync */
//#define ETH_P_FCOE	0x8906		/* Fibre Channel over Ethernet  */
//#define ETH_P_FIP	0x8914		/* FCoE Initialization Protocol */
//#define ETH_P_EDSA	0xDADA		/* Ethertype DSA [ NOT AN OFFICIALLY REGISTERED ID ] */

/*
 *	Non DIX types. Won't clash for 1500 types.
 */

//#define ETH_P_802_3	0x0001		/* Dummy type for 802.3 frames  */
//#define ETH_P_AX25	0x0002		/* Dummy protocol id for AX.25  */
//#define ETH_P_ALL	0x0003		/* Every packet (be careful!!!) */
//#define ETH_P_802_2	0x0004		/* 802.2 frames 		*/
//#define ETH_P_SNAP	0x0005		/* Internal only		*/
//#define ETH_P_DDCMP     0x0006          /* DEC DDCMP: Internal only     */
//#define ETH_P_WAN_PPP   0x0007          /* Dummy type for WAN PPP frames*/
//#define ETH_P_PPP_MP    0x0008          /* Dummy type for PPP MP frames */
//#define ETH_P_LOCALTALK 0x0009		/* Localtalk pseudo type 	*/
//#define ETH_P_CAN	0x000C		/* Controller Area Network      */
//#define ETH_P_PPPTALK	0x0010		/* Dummy type for Atalk over PPP*/
//#define ETH_P_TR_802_2	0x0011		/* 802.2 frames 		*/
//#define ETH_P_MOBITEX	0x0015		/* Mobitex (kaz@cafe.net)	*/
//#define ETH_P_CONTROL	0x0016		/* Card specific control frames */
//#define ETH_P_IRDA	0x0017		/* Linux-IrDA			*/
//#define ETH_P_ECONET	0x0018		/* Acorn Econet			*/
//#define ETH_P_HDLC	0x0019		/* HDLC frames			*/
//#define ETH_P_ARCNET	0x001A		/* 1A for ArcNet :-)            */
//#define ETH_P_DSA	0x001B		/* Distributed Switch Arch.	*/
//#define ETH_P_TRAILER	0x001C		/* Trailer switch tagging	*/
//#define ETH_P_PHONET	0x00F5		/* Nokia Phonet frames          */
//#define ETH_P_IEEE802154 0x00F6		/* IEEE802.15.4 frame		*/
//#define ETH_P_CAIF	0x00F7		/* ST-Ericsson CAIF protocol	*/

// ip proto type str
//IPPROTO_IP = 0,		/* Dummy protocol for TCP		*/
#define  IPPROTO_ICMP_STR 		"ICMP"		/* Internet Control Message Protocol	*/
#define  IPPROTO_IGMP_STR		"IGMP"		/* Internet Group Management Protocol	*/
//  IPPROTO_IPIP = 4,		/* IPIP tunnels (older KA9Q tunnels use 94) */
#define  IPPROTO_TCP_STR		"TCP"		/* Transmission Control Protocol	*/
#define  IPPROTO_EGP_STR		"EGP"		/* Exterior Gateway Protocol		*/
#define  IPPROTO_PUP_STR		"PUP"		/* PUP protocol				*/
#define  IPPROTO_UDP_STR		"UDP"		/* User Datagram Protocol		*/
#define  IPPROTO_IDP_STR		"IDP"		/* XNS IDP protocol			*/
#define  IPPROTO_DCCP_STR		"DCCP"		/* Datagram Congestion Control Protocol */
#define  IPPROTO_RSVP_STR		"RSVP"		/* RSVP protocol			*/
#define  IPPROTO_GRE_STR		"GRE"		/* Cisco GRE tunnels (rfc 1701,1702)	*/
#define  IPPROTO_IPV6_STR		"IPV6"		/* IPv6-in-IPv4 tunnelling		*/
#define  IPPROTO_ESP_STR		"ESP"		/* Encapsulation Security Payload protocol */
#define  IPPROTO_AH_STR			"AH"             /* Authentication Header protocol       */
#define  IPPROTO_BEETPH_STR		"BEETPH"	       /* IP option pseudo header for BEET */
#define  IPPROTO_PIM_STR		"PIM"		/* Protocol Independent Multicast	*/
#define  IPPROTO_COMP_STR		"COMP"		/* Compression Header protocol */
#define  IPPROTO_SCTP_STR		"SCTP"		/* Stream Control Transport Protocol	*/
#define  IPPROTO_UDPLITE_STR	"UDPLITE'"	/* UDP-Lite (RFC 3828)			*/
#define  IPPROTO_RAW_STR		"RAW"		/* Raw IP packets			*/

// hardware type str
#define ETH_STR		"eth"
#define IEEE80211_STR	"802.11"

// arp opCode str
#define ARP_REQ_STR		"ARP request"
#define ARP_RES_STR		"ARP response"
#define RARP_REQ_STR	"RARP request"
#define RARP_RES_STR	"RARP response"

char *get_arpOpCode_str(unsigned short op);

char *get_hrdtype_str(unsigned short hrd);

char *get_ip_proto_str(unsigned char proto);

unsigned char ip_proto_str_parse(char *str, int len);

char *get_proto_str(unsigned short proto);

unsigned short proto_str_parse(char *str, int len);





#define NETBIOS					137









#define ERROR_STR_FILTER_RULE			"filter rule error"
#define ERROR_STR_MALLOC				"malloc error"




#endif

