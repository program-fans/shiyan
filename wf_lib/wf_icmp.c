#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <errno.h>

#include "wf_icmp.h"

static unsigned short icmp_cal_chksum(unsigned short *addr, unsigned int len)
{
	unsigned int nleft = len;
	int sum=0;
	unsigned short *w=addr;
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

static void tv_sub(struct timeval *out, struct timeval *in)
{
	if( (out->tv_usec-=in->tv_usec)<0)
	{
		--out->tv_sec;
		out->tv_usec+=1000000;
	}
	out->tv_sec-=in->tv_sec;
}

static unsigned int icmp_pack(unsigned short icmpSeq, unsigned char icmp_type, unsigned char *data)
{
	unsigned int packsize = 0;
	struct icmp *icmp;
	struct timeval *tval;

	icmp = (struct icmp*)data;
	icmp->icmp_type = icmp_type;
	icmp->icmp_seq = icmpSeq;
	
	switch(icmp_type)
	{
	case ICMP_ECHO:
		icmp->icmp_code=0;
		icmp->icmp_cksum=0;
		icmp->icmp_id=0xa;
		packsize=8+56;
		tval= (struct timeval *)icmp->icmp_data;
		gettimeofday(tval,NULL);
		break;
	default:
		break;
	}
	if(packsize)
		icmp->icmp_cksum=icmp_cal_chksum( (unsigned short *)icmp, packsize);
	return packsize;
}

static struct icmp *icmp_unpack(unsigned char *buf, unsigned int len)
{
	int iphdrlen;
	struct ip *ip;
	struct icmp *picmp;

	ip = (struct ip *)buf;
	iphdrlen = ip->ip_hl << 2;
	picmp = (struct icmp *)(buf + iphdrlen);
	len -= iphdrlen;
	
	if( len<8){
		perror("ICMP packets\'s length is less than 8\n");
		return NULL;
	}
	return picmp;
}

int icmp_socket()
{
	int sockfd = 0, on = 1, size = 50*1024;

	sockfd = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
	if(sockfd < 0){
		perror("socket error");
		return sockfd;
	}
	setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size) );
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_BROADCAST, &on, sizeof(on));
	return sockfd;
}

int icmp_send_echo(int sockfd, unsigned short icmpSeq, char *ip)
{
	int sendlen = 0;
	unsigned int packetsize = 0;
	unsigned char sendpacket[4096];
	struct sockaddr_in dest_addr;

	if(!ip)
		return -1;
	bzero(&dest_addr,sizeof(dest_addr));
	dest_addr.sin_family=AF_INET;
	dest_addr.sin_addr.s_addr = inet_addr(ip);
	packetsize = icmp_pack(icmpSeq, ICMP_ECHO, sendpacket);
	if(packetsize){
		sendlen = sendto(sockfd, sendpacket, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr) );
		if(sendlen < 0)
			perror("icmp sendto error");
	}
	else
		perror("icmp pack error");
//	printf("icmp send to %s \n", ip);
	return sendlen;
}

int icmp_recv_echo(int sockfd, struct timeval *time_delay, struct sockaddr_in *from_addr)
{
	int n;
	socklen_t fromlen;
	unsigned char recvpacket[4096];
	struct sockaddr_in from;
	struct timeval tvrecv, *tvsend;
	struct icmp *picmp;
	
	extern int errno;

	fromlen = sizeof(from);
	if( (n=recvfrom(sockfd, recvpacket, sizeof(recvpacket), 0, (struct sockaddr *)&from, &fromlen)) <0){
		perror("icmp recvfrom error");
		return n;
	}
	gettimeofday(&tvrecv,NULL);

	picmp = icmp_unpack(recvpacket, (unsigned int)n);
	if(!picmp){
		perror("icmp unpack error");
		return -1;
	}

	if( (picmp->icmp_type == ICMP_ECHOREPLY) && (picmp->icmp_id == 0xa) ){
		if(time_delay){
			tvsend=(struct timeval *)picmp->icmp_data;
			tv_sub(&tvrecv, tvsend);
			time_delay->tv_sec = tvrecv.tv_sec;
			time_delay->tv_usec = tvrecv.tv_usec;
		}
		if(from_addr)
			memcpy(from_addr, &from, sizeof(from));
	}
	else
		return -1;
//	printf("icmp recv from %s \n", inet_ntoa(from.sin_addr));
	return 0;
}

static int tv_min(struct timeval *tv, struct timeval *tv_min)
{
	if(tv->tv_sec < tv_min->tv_sec){
		tv_min->tv_sec = tv->tv_sec;
		tv_min->tv_usec = tv->tv_usec;
		return 1;
	}
	else if((tv->tv_sec == tv_min->tv_sec) && (tv->tv_usec < tv_min->tv_usec) ){
		tv_min->tv_sec = tv->tv_sec;
		tv_min->tv_usec = tv->tv_usec;
		return 1;
	}

	return 0;
}
static void select_best_ip(int sockfd, char *ip, struct timeval *tv_avg, struct sockaddr_in *from_addr)
{
#define SEND_TIMES		2
	unsigned short icmpSeq = 0;
	struct timeval time_delay[SEND_TIMES], time_all;
	int i = 0, ret = 0, one = 1;
	
	fd_set readable;
	struct timeval wait_tv;
	int max_fd;

	for(i=0; i<SEND_TIMES; i++)
	{
		icmp_send_echo(sockfd, icmpSeq, ip);
		++icmpSeq;
		
		FD_ZERO(&readable);
		FD_SET(sockfd, &readable);
		max_fd = sockfd + 1;
		wait_tv.tv_sec = 0;
		wait_tv.tv_usec = 100000;		// 100 ms = 100 * 1000
		ret = select(max_fd, &readable, NULL, NULL, &wait_tv);
		if (ret < 0){
			if (errno == EINTR){
				--i;
				continue;
			}
//			printf("TIME_OUT     1\n");
			goto TIME_OUT;
		}
		else if (ret == 0){
//			printf("TIME_OUT     2\n");
			goto TIME_OUT;
		}
		else{
			if (FD_ISSET(sockfd, &readable)){
				if( icmp_recv_echo(sockfd, &time_delay[i], from_addr) < 0){
//					printf("TIME_OUT     3\n");
					goto TIME_OUT;
				}
			}
		}
		continue;
	TIME_OUT:
		time_delay[i].tv_sec = 0;
		time_delay[i].tv_usec = 100*1000;
	}

	if(one == SEND_TIMES){
		tv_avg->tv_sec = time_delay[0].tv_sec;
		tv_avg->tv_usec = time_delay[0].tv_usec ;
	}
	else{
		time_all.tv_sec = 0;
		time_all.tv_usec = 0;
		for(i=0; i<SEND_TIMES; i++){
			time_all.tv_sec += time_delay[i].tv_sec;
			time_all.tv_usec += time_delay[i].tv_usec;
		}

		tv_avg->tv_sec = time_all.tv_sec / SEND_TIMES;
		tv_avg->tv_usec = time_all.tv_usec / SEND_TIMES;
	}
}
int icmp_select_best_ip(char ip_list[][16], int ip_num, char *best_ip)
{
	int sockfd = 0;
	struct timeval time_delay, min_time;
	struct sockaddr_in from_addr;

	char *cur_ip = NULL, *best = NULL, ip_str[16] = {'\0'};
	int ip_idx = 0;

	if(!ip_list || !best_ip || ip_num <= 1)
		return -1;

	sockfd = icmp_socket();
	if(sockfd < 0){
		perror("socket error");
		return sockfd;
	}
	
	min_time.tv_sec = 0x0FFFFFFF;
	min_time.tv_usec = 0x0FFFFFFF;
	while(1)
	{
		if(ip_idx >= ip_num)
			break;
		cur_ip = ip_list[ip_idx];
		if(!cur_ip)
			break;
		
		select_best_ip(sockfd, cur_ip, &time_delay, &from_addr);
		printf("%s %ld  %ld \n", cur_ip, time_delay.tv_sec, time_delay.tv_usec);
		if(tv_min(&time_delay, &min_time)){
			memset(ip_str,0,sizeof(ip_str));
			strncpy(ip_str, inet_ntoa(from_addr.sin_addr), strlen(inet_ntoa(from_addr.sin_addr)));
			best = ip_str;
		}
		++ip_idx;
	}

	close(sockfd);
	if(best)
		strcpy(best_ip, best);
	else
		return -1;
	
	return 0;
}

