#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libwf.h"
#include "net_monitor.h"
#include "filter.h"

/*
static struct filter_rule *g_filter_rule[FILTER_RULE_NUM_MAX] = {0};
static int g_filter_rule_num = 0;

int add_rule(struct filter_rule *rule)
{
	if(rule == NULL || g_filter_rule_num >= FILTER_RULE_NUM_MAX)
		return -1;
	
	g_filter_rule[g_filter_rule_num] = rule;
	++g_filter_rule_num;

	return 0;
}
*/

void destory_rule();

static struct filter_rule g_filter_rule;

void rule_init()
{
	memset(&g_filter_rule, 0, sizeof(g_filter_rule));
}

void rule_enable()
{
	g_filter_rule.enable = 1;
}

void rule_disEnable()
{
	g_filter_rule.enable = 0;
}

void rule_close()
{
	rule_disEnable();
	destory_rule();
}

static void rule_proto_str_parse(char *value, struct filter_proto *proto)
{
	proto->proto = (unsigned int)proto_str_parse(value, strlen(value));
	if( proto->proto != 0 )
	{
		proto->flag = PROTO_FLAG_LEVEL_3;
		return;
	}

	proto->proto = (unsigned int)ip_proto_str_parse(value, strlen(value));
	if( proto->proto != 0 )
	{
		proto->flag = PROTO_FLAG_LEVEL_4;
		return;
	}

	proto->proto = 0;
	proto->flag = PROTO_FLAG_LEVEL_5;
}

static int rule_select_str_parse(char *select, char **p_value, enum FILTER_SELECT *p_slct)
{
	if( match_tag(select, SELECT_STR_EQUAL) )
	{
		*p_slct = FILTER_SELECT_EQUAL;
		*p_value = select + strlen(SELECT_STR_EQUAL);
		return 0;
	}
	else if( match_tag(select, SELECT_STR_NOT_EQUAL) )
	{
		*p_slct = FILTER_SELECT_NOT_EQUAL;
		*p_value = select + strlen(SELECT_STR_NOT_EQUAL);
		return 0;
	}
	else
		return -1;
}

static int rule_direct_str_parse(char *str, char **p_select, enum DIRECTION_FLAG *p_direct)
{
	char *ptr = str;
	
	if( *ptr == '.' )
	{
		++ptr;
		if( match_tag(ptr, DIRECTING_SRC_STR) )
			*p_direct = DIRECTION_FLAG_SRC;
		else if( match_tag(ptr, DIRECTING_DST_STR) )
			*p_direct = DIRECTION_FLAG_DST;
		else
			return -1;

		*p_select = ptr + 3;
	}

	return 0;
}

int rule_str_parse(char *str)
{
	char *select = NULL, *value = NULL;
	enum FILTER_SELECT slct;
	enum DIRECTION_FLAG direct = DIRECTION_FLAG_NO;

	if(str == NULL || str[0] == '\0')
		return 0;
	if( match_tag(str, RULE_STR_PROTO) )
	{
		if( g_filter_rule.proto_num >= FILTER_RULE_NUM_MAX )
			return -2;
		
		select = str + strlen(RULE_STR_PROTO);
		if( rule_select_str_parse(select, &value, &slct) < 0 )
			return -1;

		if( g_filter_rule.proto[g_filter_rule.proto_num] == NULL )
			g_filter_rule.proto[g_filter_rule.proto_num] = (struct filter_proto *)malloc(sizeof(struct filter_proto));
		if( g_filter_rule.proto[g_filter_rule.proto_num] == NULL )
			return -3;
		g_filter_rule.proto[g_filter_rule.proto_num]->select = slct;

		rule_proto_str_parse(value, g_filter_rule.proto[g_filter_rule.proto_num]);
		++g_filter_rule.proto_num;
	}
	else if( match_tag(str, RULE_STR_IP) )
	{
		if( g_filter_rule.ip_num >= FILTER_RULE_NUM_MAX )
			return -2;
		
		select = str + strlen(RULE_STR_IP);

		if( rule_direct_str_parse(select, &select, &direct) < 0 )
			return -1;
		
		if( rule_select_str_parse(select, &value, &slct) < 0 )
			return -1;

		if( g_filter_rule.ip[g_filter_rule.ip_num] == NULL )
			g_filter_rule.ip[g_filter_rule.ip_num] = (struct filter_ip *)malloc(sizeof(struct filter_ip));
		if( g_filter_rule.ip[g_filter_rule.ip_num] == NULL )
			return -3;
		g_filter_rule.ip[g_filter_rule.ip_num]->select = slct;
		g_filter_rule.ip[g_filter_rule.ip_num]->flag = direct;

		if( copyIP(value, g_filter_rule.ip[g_filter_rule.ip_num]->ip_s) < 0 )
			return -1;

		if( inet_aton(value, &g_filter_rule.ip[g_filter_rule.ip_num]->addr) == 0 )
			return -1;

		g_filter_rule.ip[g_filter_rule.ip_num]->ip_addr = g_filter_rule.ip[g_filter_rule.ip_num]->addr.s_addr;
		++g_filter_rule.ip_num;
	}
	else if( match_tag(str, RULE_STR_PORT) )
	{
		if( g_filter_rule.port_num >= FILTER_RULE_NUM_MAX )
			return -2;
		
		select = str + strlen(RULE_STR_PORT);

		if( rule_direct_str_parse(select, &select, &direct) < 0 )
			return -1;
		
		if( rule_select_str_parse(select, &value, &slct) < 0 )
			return -1;

		if( g_filter_rule.port[g_filter_rule.port_num] == NULL )
			g_filter_rule.port[g_filter_rule.port_num] = (struct filter_port *)malloc(sizeof(struct filter_port));
		if( g_filter_rule.port[g_filter_rule.port_num] == NULL )
			return -3;
		g_filter_rule.port[g_filter_rule.port_num]->select = slct;
		g_filter_rule.port[g_filter_rule.port_num]->flag = direct;

		g_filter_rule.port[g_filter_rule.port_num]->port = (unsigned short)atoi(value);
		g_filter_rule.port[g_filter_rule.port_num]->port_net= htons(g_filter_rule.port[g_filter_rule.port_num]->port);
		++g_filter_rule.port_num;
	}
	else if( match_tag(str, RULE_STR_MAC) )
	{
		if( g_filter_rule.mac_num >= FILTER_RULE_NUM_MAX )
			return -2;
		
		select = str + strlen(RULE_STR_MAC);

		if( rule_direct_str_parse(select, &select, &direct) < 0 )
			return -1;
		
		if( rule_select_str_parse(select, &value, &slct) < 0 )
			return -1;

		if( g_filter_rule.mac[g_filter_rule.mac_num] == NULL )
			g_filter_rule.mac[g_filter_rule.mac_num] = (struct filter_mac *)malloc(sizeof(struct filter_mac));
		if( g_filter_rule.mac[g_filter_rule.mac_num] == NULL )
			return -3;
		g_filter_rule.mac[g_filter_rule.mac_num]->select = slct;
		g_filter_rule.mac[g_filter_rule.mac_num]->flag = direct;

		if( str2mac(value, g_filter_rule.mac[g_filter_rule.mac_num]->mac) < 0 )
			return -1;
		++g_filter_rule.mac_num;
	}
	else
		return -1;
	
	return 0;
}

void print_rule_select(enum FILTER_SELECT slct)
{
	switch(slct)
	{
	case FILTER_SELECT_EQUAL:
		printf(" "SELECT_STR_EQUAL" ");
		break;
	case FILTER_SELECT_NOT_EQUAL:
		printf(" "SELECT_STR_NOT_EQUAL" ");
		break;
	}
}

void print_rule_proto(struct filter_proto *proto)
{
	
	
	printf(RULE_STR_PROTO);
	print_rule_select(proto->select);

	if(proto->proto == 0)
	{
		printf("unknow \n");
		return;
	}

	switch(proto->flag)
	{
	case PROTO_FLAG_LEVEL_3:
		printf("%s \n", get_proto_str((unsigned short)proto->proto));
		break;
	case PROTO_FLAG_LEVEL_4:
		printf("%s \n", get_ip_proto_str((unsigned char)proto->proto));
		break;
	case PROTO_FLAG_LEVEL_5:
		printf("unknow \n");
		break;
	}
}

void print_rule_direction(enum DIRECTION_FLAG direct)
{
	switch(direct)
	{
	case DIRECTION_FLAG_NO:
		break;
	case DIRECTION_FLAG_SRC:
		printf("."DIRECTING_SRC_STR);
		break;
	case DIRECTION_FLAG_DST:
		printf("."DIRECTING_DST_STR);
		break;
	}
}

void print_rule_ip(struct filter_ip *ip)
{
	printf(RULE_STR_IP);
	print_rule_direction(ip->flag);
	print_rule_select(ip->select);
	printf("%s \n", ip->ip_s);
}

void print_rule_port(struct filter_port *port)
{
	printf(RULE_STR_PORT);
	print_rule_direction(port->flag);
	print_rule_select(port->select);
	printf("%u \n", port->port);
}

void print_rule_mac(struct filter_mac *mac)
{
	printf(RULE_STR_MAC);
	print_rule_direction(mac->flag);
	print_rule_select(mac->select);
	printf(MAC_FORMAT_STRING" \n", MAC_FORMAT_SPLIT(mac->mac));
}

void print_rule()
{
	int i = 0;

	printf("----------- filter rules [%s]-------\n", g_filter_rule.enable ? "enable" : "disenable");
	for(i=0; i<g_filter_rule.proto_num; i++)
		print_rule_proto(g_filter_rule.proto[i]);
	for(i=0; i<g_filter_rule.ip_num; i++)
		print_rule_ip(g_filter_rule.ip[i]);
	for(i=0; i<g_filter_rule.port_num; i++)
		print_rule_port(g_filter_rule.port[i]);
	for(i=0; i<g_filter_rule.mac_num; i++)
		print_rule_mac(g_filter_rule.mac[i]);
	printf("---------------------------------------------\n");
}

void destory_rule()
{
	int i = 0;

	for(i=0; i<g_filter_rule.proto_num; i++)
		wf_free(g_filter_rule.proto[i]);
	for(i=0; i<g_filter_rule.ip_num; i++)
		wf_free(g_filter_rule.ip[i]);
	for(i=0; i<g_filter_rule.port_num; i++)
		wf_free(g_filter_rule.port[i]);
	for(i=0; i<g_filter_rule.mac_num; i++)
		wf_free(g_filter_rule.mac[i]);
}

int filter_do_mac(struct ethhdr *eth)
{
	int i=0, cmp;
	struct filter_mac *mac = NULL;

	for(i=0; i<g_filter_rule.mac_num; i++)
	{
		mac = g_filter_rule.mac[i];

		if(mac->flag == DIRECTION_FLAG_DST)
			cmp = memcmp(mac->mac, eth->h_dest, 6);
		else if(mac->flag == DIRECTION_FLAG_SRC)
			cmp = memcmp(mac->mac, eth->h_source, 6);
		else
			cmp = ( !memcmp(mac->mac, eth->h_dest, 6) || !memcmp(mac->mac, eth->h_source, 6) ) ? 0 : 1;
		
		if(mac->select == FILTER_SELECT_EQUAL)
		{
			if( cmp != 0 )
				return FILTER_DROP;
		}
		else
		{
			if( cmp == 0 )
				return FILTER_DROP;
		}
	}

	return FILTER_ACCEPT;
}

int filter_do_ip(struct iphdr *iph)
{
	int i=0, cmp;
	struct filter_ip *ip = NULL;

	for(i=0; i<g_filter_rule.ip_num; i++)
	{
		ip = g_filter_rule.ip[i];

		if(ip->flag == DIRECTION_FLAG_DST)
			cmp = (ip->ip_addr == iph->daddr) ? 0 : 1;
		else if(ip ->flag == DIRECTION_FLAG_SRC)
			cmp = (ip->ip_addr == iph->saddr) ? 0 : 1;
		else
			cmp = ( ip->ip_addr == iph->daddr || ip->ip_addr == iph->saddr ) ? 0 : 1;
		
		if(ip->select == FILTER_SELECT_EQUAL)
		{
			if( cmp != 0 )
				return FILTER_DROP;
		}
		else
		{
			if( cmp == 0 )
				return FILTER_DROP;
		}
	}

	return FILTER_ACCEPT;
}

int filter_do_port(unsigned short src_port, unsigned short dst_port)
{
	int i=0, cmp;
	struct filter_port *port = NULL;

	for(i=0; i<g_filter_rule.port_num; i++)
	{
		port = g_filter_rule.port[i];

		if(port->flag == DIRECTION_FLAG_DST)
			cmp = (port->port_net == dst_port) ? 0 : 1;
		else if(port->flag == DIRECTION_FLAG_SRC)
			cmp = (port->port_net == src_port) ? 0 : 1;
		else
			cmp = ( port->port_net == dst_port || port->port_net == src_port ) ? 0 : 1;
		
		if(port->select == FILTER_SELECT_EQUAL)
		{
			if( cmp != 0 )
				return FILTER_DROP;
		}
		else
		{
			if( cmp == 0 )
				return FILTER_DROP;
		}
	}

	return FILTER_ACCEPT;
}

int filter_do_proto(unsigned int proto_id, enum PROTO_FLAG level)
{
	int i=0, cmp;
	struct filter_proto *proto = NULL;
	//printf("into filter_proto [proto_id: %x, level: %d] \n", proto_id, level);
	for(i=0; i<g_filter_rule.proto_num; i++)
	{
		proto = g_filter_rule.proto[i];
		//printf("proto: %x, levle: %d \n", proto->proto, proto->flag);
		if(proto->flag != level)
			continue;

		cmp = (proto->proto == proto_id) ? 0 : 1;

		if(proto->select == FILTER_SELECT_EQUAL)
		{
			if( cmp != 0 )
				return FILTER_DROP;
		}
		else
		{
			if( cmp == 0 )
				return FILTER_DROP;
		}
	}

	return FILTER_ACCEPT;
}

int filter_level_5(unsigned char *buf, int len)
{
	return FILTER_ACCEPT;
}
	
int filter_level_tcp(unsigned char *buf, int len)
{
	struct tcphdr *tcph;
	int hlen;
	
	if(buf == NULL || len < sizeof(struct tcphdr))
		return FILTER_ACCEPT;
	tcph = (struct tcphdr *)buf;
	hlen = (int)(tcph->doff * 4);
	
	if( filter_do_port(tcph->source, tcph->dest) == FILTER_DROP )
		return FILTER_DROP;
	
	if( filter_level_5(buf + hlen, len - hlen) == FILTER_DROP )
		return FILTER_DROP;

	return FILTER_ACCEPT;
}

int filter_level_udp(unsigned char *buf, int len)
{
	struct udphdr *udph;
	if(buf == NULL || len < sizeof(struct udphdr))
		return FILTER_ACCEPT;
	udph = (struct udphdr *)buf;
	
	if( filter_do_port(udph->source, udph->dest) == FILTER_DROP )
		return FILTER_DROP;

	if( filter_level_5(buf + sizeof(struct udphdr), len - sizeof(struct udphdr)) == FILTER_DROP )
		return FILTER_DROP;
	
	return FILTER_ACCEPT;
}

int filter_level_3(unsigned char *buf, int len)
{	
	struct iphdr *iph;
	int hlen;

	if(buf == NULL || len < sizeof(struct iphdr))
		return FILTER_ACCEPT;
	iph = (struct iphdr *)buf;
	hlen = (int)(iph->ihl * 4);
	
	if( filter_do_ip(iph) == FILTER_DROP )
		return FILTER_DROP;
	if( filter_do_proto((unsigned int)iph->protocol, PROTO_FLAG_LEVEL_4) == FILTER_DROP )
		return FILTER_DROP;

	if( iph->protocol == IPPROTO_TCP )
	{
		if( filter_level_tcp(buf + hlen, len - hlen) == FILTER_DROP )
			return FILTER_DROP;
	}
	else if( iph->protocol == IPPROTO_UDP )
	{
		if( filter_level_udp(buf + hlen, len - hlen) == FILTER_DROP )
			return FILTER_DROP;
	}
	else
		return FILTER_ACCEPT;

	return FILTER_ACCEPT;
}

int filter_level_2(unsigned char *buf, int len)
{
	struct ethhdr *eth;
	unsigned short proto;
	
	if(buf == NULL || len < sizeof(struct ethhdr))
		return FILTER_ACCEPT;
	eth = (struct ethhdr *)buf;
	proto = ntohs(eth->h_proto);
	
	if( filter_do_mac(eth) == FILTER_DROP )
		return FILTER_DROP;
	if( filter_do_proto((unsigned int)proto, PROTO_FLAG_LEVEL_3) == FILTER_DROP )
		return FILTER_DROP;

	if( proto != ETH_P_IP)
		return FILTER_ACCEPT;

	if( filter_level_3(buf + sizeof(struct ethhdr), len - sizeof(struct ethhdr)) == FILTER_DROP )
		return FILTER_DROP;
	
	return FILTER_ACCEPT;
}

int filter(unsigned char *buf, int len)
{
	if( !g_filter_rule.enable )
		return FILTER_ACCEPT;
	
	if( filter_level_2(buf, len) == FILTER_DROP )
		return FILTER_DROP;

	return FILTER_ACCEPT;
}

