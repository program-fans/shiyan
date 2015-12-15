#include "net_monitor.h"

char *get_arpOpCode_str(unsigned short op)
{
	switch(op)
	{
	case 1: return ARP_REQ_STR;
		break;
	case 2: return ARP_RES_STR;
		break;
	case 3: return RARP_REQ_STR;
		break;
	case 4: return RARP_RES_STR;
		break;
	default: return OTHER_STR;
		break;
	}
}

char *get_hrdtype_str(unsigned short hrd)
{
	switch(hrd)
	{
	case ARPHRD_ETHER: return ETH_STR;
		break;
	case ARPHRD_IEEE80211: return IEEE80211_STR;
		break;
	default: return OTHER_STR;
		break;
	}
}

char *get_ip_proto_str(unsigned char proto)
{
	switch(proto)
	{
//	case IPPROTO_IP:										// 0
//		break;
	case IPPROTO_ICMP: return IPPROTO_ICMP_STR;				// 1
		break;
	case IPPROTO_IGMP: return IPPROTO_IGMP_STR;				// 2
		break;
//	case IPPROTO_IPIP:										// 4
//		break;
	case IPPROTO_TCP: return IPPROTO_TCP_STR;				// 6
		break;
	case IPPROTO_EGP: return IPPROTO_EGP_STR;				// 8
		break;
	case IPPROTO_PUP: return IPPROTO_PUP_STR;				// 12
		break;
	case IPPROTO_UDP: return IPPROTO_UDP_STR;				// 17
		break;
	case IPPROTO_IDP: return IPPROTO_IDP_STR;					// 22
		break;
	case IPPROTO_DCCP: return IPPROTO_DCCP_STR;				// 33
		break;
	case IPPROTO_RSVP: return IPPROTO_RSVP_STR;				// 46
		break;
	case IPPROTO_GRE: return IPPROTO_GRE_STR;				// 47
		break;
	case IPPROTO_IPV6: return IPPROTO_IPV6_STR;				// 41
		break;
	case IPPROTO_ESP: return IPPROTO_ESP_STR;				// 50
		break;
	case IPPROTO_AH: return IPPROTO_AH_STR;					// 51
		break;
//	case IPPROTO_BEETPH: return IPPROTO_BEETPH_STR;			// 94
//		break;
	case IPPROTO_PIM: return IPPROTO_PIM_STR;				// 103
		break;
	case IPPROTO_COMP: return IPPROTO_COMP_STR;				// 108
		break;
	case IPPROTO_SCTP: return IPPROTO_SCTP_STR;				// 132
		break;
	case IPPROTO_UDPLITE: return IPPROTO_UDPLITE_STR;			// 136
		break;
	case IPPROTO_RAW: return IPPROTO_RAW_STR;				// 255
		break;
	default:	return OTHER_STR;
		break;
	}
}

unsigned char ip_proto_str_parse(char *str, int len)
{
	if( strnicmp_2(str, IPPROTO_ICMP_STR, len) == 0)
		return IPPROTO_ICMP;
	else if( strnicmp_2(str, IPPROTO_IGMP_STR, len) == 0)
		return IPPROTO_IGMP;
	else if( strnicmp_2(str, IPPROTO_TCP_STR, len) == 0)
		return IPPROTO_TCP;
	else if( strnicmp_2(str, IPPROTO_EGP_STR, len) == 0)
		return IPPROTO_EGP;
	else if( strnicmp_2(str, IPPROTO_PUP_STR, len) == 0)
		return IPPROTO_PUP;
	else if( strnicmp_2(str, IPPROTO_UDP_STR, len) == 0)
		return IPPROTO_UDP;
	else if( strnicmp_2(str, IPPROTO_IDP_STR, len) == 0)
		return IPPROTO_IDP;
	else if( strnicmp_2(str, IPPROTO_DCCP_STR, len) == 0)
		return IPPROTO_DCCP;
	else if( strnicmp_2(str, IPPROTO_RSVP_STR, len) == 0)
		return IPPROTO_RSVP;
	else if( strnicmp_2(str, IPPROTO_GRE_STR, len) == 0)
		return IPPROTO_GRE;
	else if( strnicmp_2(str, IPPROTO_IPV6_STR, len) == 0)
		return IPPROTO_IPV6;
	else if( strnicmp_2(str, IPPROTO_ESP_STR, len) == 0)
		return IPPROTO_ESP;
	else if( strnicmp_2(str, IPPROTO_AH_STR, len) == 0)
		return IPPROTO_AH;
//	else if( strnicmp_2(str, IPPROTO_BEETPH_STR, len) == 0)
//		return IPPROTO_BEETPH;
	else if( strnicmp_2(str, IPPROTO_PIM_STR, len) == 0)
		return IPPROTO_PIM;
	else if( strnicmp_2(str, IPPROTO_COMP_STR, len) == 0)
		return IPPROTO_COMP;
	else if( strnicmp_2(str, IPPROTO_SCTP_STR, len) == 0)
		return IPPROTO_SCTP;
	else if( strnicmp_2(str, IPPROTO_UDPLITE_STR, len) == 0)
		return IPPROTO_UDPLITE;
	else if( strnicmp_2(str, IPPROTO_RAW_STR, len) == 0)
		return IPPROTO_RAW;
	else 
		return 0;
}

char *get_proto_str(unsigned short proto)
{
	switch(proto)
	{
	case ETH_P_IP: return ETH_P_IP_STR;				// 0x0800
		break;
	case ETH_P_ARP: return ETH_P_ARP_STR;			// 0x0806
		break;
	case ETH_P_AARP: return ETH_P_AARP_STR;			// 0x80F3
		break;
	case ETH_P_IPV6: return ETH_P_IPV6_STR;			// 0x86DD
		break;
	default: return OTHER_STR;
		break;
	}
}

unsigned short proto_str_parse(char *str, int len)
{
	if( strnicmp_2(str, ETH_P_IP_STR, len) == 0)
		return ETH_P_IP;
	else if( strnicmp_2(str, ETH_P_ARP_STR, len) == 0)
		return ETH_P_ARP;
	else if( strnicmp_2(str, ETH_P_AARP_STR, len) == 0)
		return ETH_P_AARP;
	else if( strnicmp_2(str, ETH_P_IPV6_STR, len) == 0)
		return ETH_P_IPV6;
	else 
		return 0;
}

