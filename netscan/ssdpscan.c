#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <arpa/inet.h>  //for in_addr   inet_ntoa
//#include "net_packet.h"
//#include "netscan.h"
#include "libwf.h"

#if 1
#define DEBUG(fmt, ...)	do{if(1)printf("[%s-%d] "fmt, __FILE__, __LINE__, ##__VA_ARGS__);}while(0)
#define print_data(buff, size)	print_strn(buff, size)
#else
#define DEBUG(fmt, ...)	do{}while(0)
#define print_data(buff, size)
#endif
#if 1
#define ERROR(fmt, ...)	do{if(1)printf(fmt, ##__VA_ARGS__);}while(0)
#else
#define ERROR(fmt, ...)	do{}while(0)
#endif

struct ssdpscan_t
{
	unsigned int listen_timeout;
	unsigned int discover_tm;
	int ssdp_sock;
	int discover_sock;
};

#define SSDP_LISTEN_PORT	1900
#define SSDP_LISTEN_IP		"239.255.255.250"

#define SSDP_DISCOVER_MX	3

int ssdp_listen_socket()
{
	int sock = 0;
	struct sockaddr_in addr;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock < 0){
		perror("socket error");
		return sock;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(SSDP_LISTEN_PORT);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if(bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) < 0){
		perror("bind error");
		close(sock);
		return -1;
	}
	
	if(setsock_multi(sock, SSDP_LISTEN_IP) < 0){
		perror("setsock_multi error");
		close(sock);
		return -1;
	}

	return sock;
}

int read_ssdp_sock(struct ssdpscan_t *ssdp_scan)
{
	int len=0;
	char buff[2048] = {'\0'};
	socklen_t sockaddr_len = sizeof(struct sockaddr_in);
	struct sockaddr_in addr_from;
	struct sockaddr *paddr = (struct sockaddr *)&addr_from;

	memset(&addr_from, 0, sizeof(addr_from));

	len = recvfrom(ssdp_scan->ssdp_sock, buff, sizeof(buff), 0, paddr, &sockaddr_len);
	if(len <= 0)
		return len;
	print_data(buff, len);
	
	return len;
}

int discover_proc(struct ssdpscan_t *ssdp_scan)
{
	char buff[1024] = {'\0'};
	struct sockaddr_in addr_to;
	int ret = 0, sock = 0;
	
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock < 0){
		perror("socket error");
		return sock;
	}
	DEBUG("open discover socket: %d \n", sock);

	sprintf(buff, "M-SEARCH * HTTP/1.1\r\n"
			"HOST: %s:%d\r\n"
			//"MAN: \"ssdp:discover\"\r\n"
			"MAN: ssdp:discover\r\n"
			"MX: %d\r\n"
			"ST: UPnP:rootdevice\r\n", SSDP_LISTEN_IP, SSDP_LISTEN_PORT, SSDP_DISCOVER_MX);

	memset(&addr_to, 0, sizeof(addr_to));
	addr_to.sin_family = AF_INET;
	addr_to.sin_port = htons(SSDP_LISTEN_PORT);
	addr_to.sin_addr.s_addr = inet_addr(SSDP_LISTEN_IP);

	ret = sendto(ssdp_scan->ssdp_sock, buff, strlen(buff), 0, (struct sockaddr *)&addr_to,sizeof(struct sockaddr));
	if(ret < 0){
		perror("sendto error");
		close(sock);
		return -1;
	}

	ssdp_scan->discover_sock = sock;
	
	return 0;
}

int read_discover_sock(struct ssdpscan_t *ssdp_scan)
{
	int len=0;
	char buff[2048] = {'\0'};
	socklen_t sockaddr_len = sizeof(struct sockaddr_in);
	struct sockaddr_in addr_from;
	struct sockaddr *paddr = (struct sockaddr *)&addr_from;

	memset(&addr_from, 0, sizeof(addr_from));

	len = recvfrom(ssdp_scan->discover_sock, buff, sizeof(buff), 0, paddr, &sockaddr_len);
	if(len <= 0)
		return len;
	print_data(buff, len);
	
	return len;
}

int close_discover(struct ssdpscan_t *ssdp_scan)
{
	if(ssdp_scan->discover_sock > 0){
		DEBUG("close discover socket: %d \n", ssdp_scan->discover_sock);
		close(ssdp_scan->discover_sock);
		ssdp_scan->discover_sock = 0;
	}

	return 0;
}

int ssdp_scan_proc(struct ssdpscan_t *ssdp_scan)
{
	int listen_sock = -1;
	int max_fd = 0, ret = 0, discover = 0;
	fd_set fds;
	struct timeval tv;
	unsigned long start_tm = 0, now_tm = 0, last_tm = 0, diff_tm = 0;
	
	wf_getsys_uptime(&start_tm);
	last_tm = start_tm - ssdp_scan->discover_tm;
	
	listen_sock = ssdp_listen_socket();
	if(listen_sock < 0){
		return listen_sock;
	}
	ssdp_scan->ssdp_sock = listen_sock;

	while(1)
	{
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		FD_ZERO(&fds);
		WF_FD_SET(listen_sock, &fds, max_fd);
		if(discover && ssdp_scan->discover_sock > 0)
			WF_FD_SET(ssdp_scan->discover_sock, &fds, max_fd);

		ret = select(max_fd+1, &fds, NULL, NULL, &tv);
		if(ret < 0)
		{
			if(errno == EINTR || errno == EAGAIN)
				continue;
		}
		else if(ret > 0){
			if( FD_ISSET(listen_sock, &fds) )
				read_ssdp_sock(ssdp_scan);
			if(discover && FD_ISSET(ssdp_scan->discover_sock, &fds)){
				read_discover_sock(ssdp_scan);
				discover = 0;
			}
		}

		wf_getsys_uptime(&now_tm);
		if((now_tm - start_tm) >= ssdp_scan->listen_timeout)
			break;
		
		if(ssdp_scan->listen_timeout){
			diff_tm = now_tm - last_tm;
			if(discover && diff_tm >= SSDP_DISCOVER_MX){
				close_discover(ssdp_scan);
				discover = 0;
			}

			if(diff_tm >= ssdp_scan->discover_tm){
				if(discover){
					close_discover(ssdp_scan);
					discover = 0;
				}
					
				last_tm = now_tm;
				if(discover_proc(ssdp_scan) == 0){
					discover = 1;
				}
			}
		}
	}
	close_discover(ssdp_scan);
	close(listen_sock);
	ssdp_scan->ssdp_sock = 0;

	return 0;
}

void ssdpscan_usage()
{
	fprintf(stderr, "ssdpscan usage: \n"
		"ssdpscan [-t listen timeout] [-d discover timeout] \n"
		);
}

struct ssdpscan_t g_sddp_scan;
#if 1
int ssdpscan_main(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
{
	int ch;
	
	g_sddp_scan.listen_timeout = 200;
	g_sddp_scan.discover_tm = 6;

	while((ch = getopt(argc, argv, "t:d:")) != -1)
	{
		switch(ch)
		{
		case 't':g_sddp_scan.listen_timeout = atoi(optarg);
			break;
		case 'd':g_sddp_scan.discover_tm = atoi(optarg);
			break;
		default:
			printf("invalid option: %c \n", ch);
			exit(0);
			break;
		}
	}

	ssdp_scan_proc(&g_sddp_scan);

	return 0;
}

