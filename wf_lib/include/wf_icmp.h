#ifndef WF_ICMP_H_
#define WF_ICMP_H_


#include <netinet/in.h>

extern int icmp_socket();

extern int icmp_send_echo(int sockfd, unsigned short icmpSeq, char *ip);

extern int icmp_recv_echo(int sockfd, struct timeval *time_delay, struct sockaddr_in *from_addr);

extern int icmp_select_best_ip(char ip_list[][16], int ip_num, char *best_ip);

#endif

