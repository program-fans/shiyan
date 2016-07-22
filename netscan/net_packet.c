#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "net_packet.h"
#include "libwf.h"

struct net_packet
{
	unsigned char *buff;
	unsigned int buff_len;
	struct ethhdr *eth;
	struct iphdr *iph;
	union{
		struct tcphdr *tcph;
		struct udphdr *udph;
		struct icmp *icmph;
	}trans;
	unsigned char *load_data;
	unsigned int data_len;
};


unsigned int pack_ethhdr(struct ethhdr *eth, unsigned char *buff)
{
	eth->h_proto = htons(eth->h_proto);
	memcpy(buff, eth, sizeof(struct ethhdr));

	return sizeof(struct ethhdr);
}

unsigned int pack_iphdr(struct iphdr *iph, unsigned char *opt, unsigned int opt_len, unsigned char *buff)
{
	unsigned int pad_size = 0, op_cp = 0;
	unsigned char pad[4] = {0};

	iph->tot_len = htons(iph->tot_len);
	iph->id = htons(iph->id);
	iph->frag_off = htons(iph->frag_off);
	iph->check = htons(iph->check);

	if(opt && opt_len){
		if(opt_len >= 40){
			iph->ihl = 15;
			op_cp = 40;
		}
		else{
			pad_size = 4 - (opt_len%4);
			if(pad_size == 4)
				pad_size = 0;
			iph->ihl = (sizeof(struct iphdr) + opt_len + pad_size) / 4;
			op_cp = opt_len;
		}
	}
	else
		iph->ihl = 5;
	
	memcpy(buff, iph, sizeof(struct iphdr));
	if(op_cp)
		memcpy(buff, opt, op_cp);
	if(pad_size)
		memcpy(buff, pad, pad_size);

	return (sizeof(struct iphdr) + op_cp + pad_size);
}

unsigned int pack_tcphdr(struct tcphdr *tcph, unsigned char *opt, unsigned int opt_len, unsigned char *buff)
{
	unsigned int pad_size = 0, op_cp = 0;
	unsigned char pad[4] = {0};

	tcph->source = htons(tcph->source);
	tcph->dest = htons(tcph->dest);
	tcph->seq = htonl(tcph->seq);
	tcph->ack_seq = htonl(tcph->ack_seq);
	tcph->window = htons(tcph->window);
	tcph->check = htons(tcph->check);
	tcph->urg_ptr = htons(tcph->urg_ptr);

	if(opt && opt_len){
		if(opt_len >= 40){
			tcph->doff = 15;
			op_cp = 40;
		}
		else{
			pad_size = 4 - (opt_len%4);
			if(pad_size == 4)
				pad_size = 0;
			tcph->doff = (sizeof(struct tcphdr) + opt_len + pad_size) / 4;
			op_cp = opt_len;
		}
	}
	else
		tcph->doff = 5;

	memcpy(buff, tcph, sizeof(struct tcphdr));
	if(op_cp)
		memcpy(buff, opt, op_cp);
	if(pad_size)
		memcpy(buff, pad, pad_size);

	return (sizeof(struct tcphdr) + op_cp + pad_size);
}





unsigned short complement_checksum(unsigned short *buff, unsigned int size)
{
	unsigned int nleft = size;
	unsigned int sum=0;
	unsigned short *w=buff;
	unsigned short answer=0;

	while(nleft>1)
	{
		sum+=*w++;
		nleft-=2;
	}
	if( nleft==1)
	{
		*(unsigned char *)(&answer)=*(unsigned char *)w;
		sum+=answer;
	}
	sum=(sum>>16)+(sum&0xffff);
	sum+=(sum>>16);
	answer=~sum;
	return answer;
}

unsigned short ip_checksum(struct iphdr *iph, unsigned char *option, unsigned int opt_len)
{
	unsigned char buff[60] = {0};
	unsigned short *pbuf = (unsigned short *)iph;
	unsigned int size = iph->ihl * 4, len = 0;

	if(option && opt_len){
		if(opt_len > 40)
			len = 40;
		else
			len = opt_len;
		memcpy(buff, iph, sizeof(struct iphdr));
		memcpy(buff + sizeof(struct iphdr), option, len);
		pbuf = (unsigned short *)&buff[0];
	}

	return complement_checksum(pbuf, size);
}

int tcp_set_option(struct tcp_option *opt, int option, void *arga, void *argb)
{
	unsigned char *p_c, tmp_c, pad[4] = {0};
	unsigned short *p_short, tmp_short;
	unsigned int *p_int, tmp_int;
	if(!opt || opt->len > 40)
		return -1;
	switch(option)
	{
	case TCPOPT_NOP:
		if(opt->len > 39)		// 40 - 1
			return -1;
		tmp_c = 0x01; opt->buff[opt->len] = tmp_c; ++opt->len;
		break;
	case TCPOPT_MSS:
		p_short = (unsigned short *)arga;
		if(!p_short)
			return -1;
		if(opt->len > 36)		// 40 - 4
			return -1;
		tmp_c = 0x02; opt->buff[opt->len] = tmp_c; ++opt->len;
		tmp_c = 0x04; opt->buff[opt->len] = tmp_c; ++opt->len;
		tmp_short = htons(*p_short);
		memcpy(opt->buff+ opt->len, &tmp_short, 2);
		opt->len += 2;
		break;
	case TCPOPT_WS:
		p_c = (unsigned char *)arga;
		if(!p_c)
			return -1;
		if(opt->len > 37)		// 40 - 3
			return -1;
		tmp_c = 0x03; opt->buff[opt->len] = tmp_c; ++opt->len;
		tmp_c = 0x03; opt->buff[opt->len] = tmp_c; ++opt->len;
		opt->buff[opt->len] = *p_c;
		++opt->len;
		break;
	case TCPOPT_SACK:
		if(opt->len > 38)		// 40 - 2
			return -1;
		tmp_c = 0x04; opt->buff[opt->len] = tmp_c; ++opt->len;
		tmp_c = 0x02; opt->buff[opt->len] = tmp_c; ++opt->len;
		break;
	case TCPOPT_TSVAL:
		if(!arga || !argb)
			return -1;
		if(opt->len > 30)		// 40 - 10
			return -1;
		tmp_c = 0x08; opt->buff[opt->len] = tmp_c; ++opt->len;
		tmp_c = 0x0A; opt->buff[opt->len] = tmp_c; ++opt->len;
		p_int = (unsigned int *)arga;
		tmp_int = htonl(*p_int);
		memcpy(opt->buff+ opt->len, &tmp_int, 4);
		opt->len += 4;
		p_int = (unsigned int *)argb;
		tmp_int = htonl(*p_int);
		memcpy(opt->buff+ opt->len, &tmp_int, 4);
		opt->len += 4;
		break;
	case TCPOPT_PADD:
		tmp_int = 4 - (opt->len % 4);
		if(tmp_int < 4){
			memcpy(opt->buff + opt->len, pad, tmp_int);
			opt->len += tmp_int;
		}
		break;
	default:
		return -1;
	}
	set_bit(option, &opt->option);
	return 0;
}

unsigned short tcp_checksum(struct fake_tcpudphdr *fake_tcph, struct tcphdr *tcph, struct tcp_option *topt)
{
	unsigned char buff[72] = {0};
	unsigned short *pbuf = (unsigned short *)&buff[0], tmp_short;
	unsigned int size = tcph->doff * 4, buf_len = 0, tmp_size;
#if 1
	if(topt && topt->len){
		if(!test_bit(TCPOPT_PADD, &topt->option)){
			tcp_set_option(topt, TCPOPT_PADD, NULL, NULL);
		}
		tmp_size = topt->len + sizeof(struct tcphdr);
		if(size != tmp_size){
			printf("rset tcph->doff \n");
			tcph->doff = tmp_size >> 2;
			size = tmp_size;
		}
		tmp_short = htons((unsigned short)size);
		if(fake_tcph->len != tmp_short){
			printf("rset fake_tcph->len \n");
			fake_tcph->len = tmp_short;
		}
	}
#endif
	memcpy(buff, fake_tcph, sizeof(struct fake_tcpudphdr));
	buf_len = sizeof(struct fake_tcpudphdr);
	memcpy(buff + buf_len, tcph, sizeof(struct tcphdr));
	buf_len += sizeof(struct tcphdr);

	if(topt && topt->len){
		memcpy(buff + buf_len, topt->buff, topt->len);
		buf_len += topt->len;
	}

	return complement_checksum(pbuf, buf_len);
}

unsigned int pack_iptcp_syn_option(struct sockaddr_in *saddr, struct sockaddr_in *daddr, unsigned char *buff)
{
	struct iphdr iph;
	struct tcphdr tcph;
	struct fake_tcpudphdr fake_tcph;
	unsigned int len = 0, tcp_hlen = sizeof(struct tcphdr);

	unsigned short mss = 1460;
	unsigned int tsval = 0, tsecr = 0;
	unsigned char ws = 7;
	struct tcp_option topt;
	
	memset(&topt, 0, sizeof(topt));
	tcp_set_option(&topt, TCPOPT_MSS, &mss, NULL);
	tcp_set_option(&topt, TCPOPT_SACK, NULL, NULL);
	tsval = (unsigned int)time(NULL);
	tcp_set_option(&topt, TCPOPT_TSVAL, &tsval, &tsecr);
	tcp_set_option(&topt, TCPOPT_NOP, NULL, NULL);
	tcp_set_option(&topt, TCPOPT_WS, &ws, NULL);
	tcp_set_option(&topt, TCPOPT_PADD, NULL, NULL);
	tcp_hlen += topt.len;
	
	tcph.source = saddr->sin_port;
	tcph.dest = daddr->sin_port;
	tcph.seq = random();
	tcph.ack_seq = 0;
	tcph.doff = (unsigned short)tcp_hlen >> 2;
	tcph.res1 = 0;
	tcph.cwr = 0;
	tcph.ece = 0;
	tcph.urg = 0;
	tcph.ack = 0;
	tcph.psh = 0;
	tcph.rst = 0;
	tcph.syn = 1;
	tcph.fin = 0;
	tcph.window = htons(14600);
	tcph.check = 0;
	tcph.urg_ptr = 0;

	iph.version = 4;
	iph.ihl = sizeof(struct iphdr) >> 2;
	iph.tos = 0;
	iph.tot_len = htons((unsigned short)(sizeof(struct iphdr) + tcp_hlen));
	//iph.id = 0;
	iph.id = htons((unsigned short)random());
	iph.frag_off = htons(0x4000);		// don't fragment
	iph.ttl = 128;
	iph.protocol = IPPROTO_TCP;
	iph.check = 0;
	iph.saddr = saddr->sin_addr.s_addr;
	iph.daddr = daddr->sin_addr.s_addr;
	//iph.check = ip_checksum(&iph, NULL, 0);		// no need htons
	
	fake_tcph.saddr = iph.saddr;
	fake_tcph.daddr = iph.daddr;
	fake_tcph.pad = 0;
	fake_tcph.protocol = iph.protocol;
	fake_tcph.len = htons((unsigned short)tcp_hlen);
	
	tcph.check = tcp_checksum(&fake_tcph, &tcph, &topt);		// no need htons

	memcpy(buff, &iph, sizeof(struct iphdr));
	len = sizeof(struct iphdr);
	memcpy(buff + len, &tcph, sizeof(struct tcphdr));
	len += sizeof(struct tcphdr);
	memcpy(buff + len, topt.buff, topt.len);
	len += topt.len;

	return len;
}

unsigned int pack_iptcp_syn(struct sockaddr_in *saddr, struct sockaddr_in *daddr, unsigned char *buff)
{
	struct iphdr iph;
	struct tcphdr tcph;
	struct fake_tcpudphdr fake_tcph;
	unsigned int len = 0, tcp_hlen = sizeof(struct tcphdr);
		
	tcph.source = saddr->sin_port;
	tcph.dest = daddr->sin_port;
	tcph.seq = random();
	tcph.ack_seq = 0;
	tcph.doff = (unsigned short)tcp_hlen >> 2;
	tcph.res1 = 0;
	tcph.cwr = 0;
	tcph.ece = 0;
	tcph.urg = 0;
	tcph.ack = 0;
	tcph.psh = 0;
	tcph.rst = 0;
	tcph.syn = 1;
	tcph.fin = 0;
	tcph.window = htons(14600);
	tcph.check = 0;
	tcph.urg_ptr = 0;

	iph.version = 4;
	iph.ihl = sizeof(struct iphdr) >> 2;
	iph.tos = 0;
	iph.tot_len = htons((unsigned short)(sizeof(struct iphdr) + tcp_hlen));
	//iph.id = 0;
	iph.id = htons((unsigned short)random());
	iph.frag_off = htons(0x4000);		// don't fragment
	iph.ttl = 128;
	iph.protocol = IPPROTO_TCP;
	iph.check = 0;
	iph.saddr = saddr->sin_addr.s_addr;
	iph.daddr = daddr->sin_addr.s_addr;
	//iph.check = ip_checksum(&iph, NULL, 0);		// no need htons
	
	fake_tcph.saddr = iph.saddr;
	fake_tcph.daddr = iph.daddr;
	fake_tcph.pad = 0;
	fake_tcph.protocol = iph.protocol;
	fake_tcph.len = htons((unsigned short)tcp_hlen);
	
	tcph.check = tcp_checksum(&fake_tcph, &tcph, NULL);		// no need htons

	memcpy(buff, &iph, sizeof(struct iphdr));
	len = sizeof(struct iphdr);
	memcpy(buff + len, &tcph, sizeof(struct tcphdr));
	len += sizeof(struct tcphdr);

	return len;
}


