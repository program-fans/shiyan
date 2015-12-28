#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include "wf_char.h"
#include "wf_net.h"

int getHostIP_2(char *prior_if, char *ip, char *broadip, char *ifname, int *ifindex)
{
	int leng = sizeof(struct sockaddr_in);
	int sockfd;
	int i=0;
	struct ifreq ifr;
	struct ifconf icf;
	unsigned char buf[512]={0};
	struct ifreq *ifrp=NULL;
	memset(&ifr, 0, sizeof(struct ifreq));
	memset(&icf, 0, sizeof(struct ifconf));
	//初始化ifconf
	icf.ifc_len = 512;
	icf.ifc_buf = (caddr_t)buf;

	if((sockfd = socket(AF_INET, SOCK_DGRAM, 0))<0)	return -1;
	
	ioctl(sockfd, SIOCGIFCONF, &icf);    //获取所有接口信息
	//接下来一个一个的获取IP地址
	//ifrp = (struct ifreq*)buf; 
	ifrp = icf.ifc_req;
	for(i=(icf.ifc_len/sizeof(struct ifreq)); i>0; i--)
	{
		if(ifrp->ifr_flags == AF_INET)            //for ipv4
		{
			//发送命令，获得网络接口的广播地址
			if (ioctl(sockfd, SIOCGIFBRDADDR, ifrp) == -1)	continue;
			if(broadip)	sprintf(broadip,"%s", inet_ntoa(((struct sockaddr_in*)&(ifrp->ifr_broadaddr))->sin_addr));

			//printf("broadip: %s \n", inet_ntoa(((struct sockaddr_in*)&(ifrp->ifr_broadaddr))->sin_addr));

			if (ioctl(sockfd, SIOCGIFADDR, ifrp ) == -1)	continue;
			if(ip)	sprintf(ip,"%s",inet_ntoa(((struct sockaddr_in*)&(ifrp->ifr_addr))->sin_addr));
			if( ifname )	sprintf(ifname, "%s", ifrp->ifr_name);
			if(ifindex)	*ifindex = ifrp->ifr_ifindex;
			//printf("ip: %s if: %s \n", inet_ntoa(((struct sockaddr_in*)&(ifrp->ifr_addr))->sin_addr), ifrp->ifr_name);
			
			if(prior_if && strncmp(ifrp->ifr_name, prior_if, strlen(prior_if)) == 0 )	break;
  		}
		ifrp++;
	}
	close(sockfd);
	
	return 0;
}
int getHostIP(char *prior_if, char *ip, char *broadip, char *ifname)
{
	return getHostIP_2(prior_if, ip, broadip, ifname, NULL);
}

int getIP_byCmd(char *ip)
{
	FILE *fp = popen("ifconfig | grep inet | sed -n '1p' | awk '{print $2}' | awk -F ':' '{print $2}'", "r");//打开管道，执行shell 命令
	char buffer[1024] = {0};
	int num=0;
	while (NULL != fgets(buffer, 1024, fp)) //逐行读取执行结果并打印
	{
		wipe_off_CRLF_inEnd(buffer);
		if(ip)
			strcpy(ip,buffer);
		num += 1;
	}
	pclose(fp); //关闭返回的文件指针，注意不是用fclose噢
	
	return num;
}
int getMAC_byCmd(char *mac)
{
	FILE *fp = popen("ifconfig | grep eth0 | awk '{print $5}'", "r");//打开管道，执行shell 命令
	char buffer[1024] = {0};
	int num=0,len=0;
	while (NULL != fgets(buffer, 1024, fp)) //逐行读取执行结果并打印
	{
		wipe_off_CRLF_inEnd(buffer);
		if(mac)
			strcpy(mac,buffer);
		num += 1;
	}
	pclose(fp); //关闭返回的文件指针，注意不是用fclose噢
	
	return num;
}
int getMASK_byCmd(char *mask)
{
	FILE *fp = popen("ifconfig | grep inet | sed -n '1p' | awk '{print $4}' | awk -F ':' '{print $2}'", "r");//打开管道，执行shell 命令
	char buffer[1024] = {0};
	int num=0;
	while (NULL != fgets(buffer, 1024, fp)) //逐行读取执行结果并打印
	{
		wipe_off_CRLF_inEnd(buffer);
		if(mask)
			strcpy(mask,buffer);
		num += 1;
	}
	pclose(fp); //关闭返回的文件指针，注意不是用fclose噢
	
	return num;
}
int getGW_byCmd(char *gw)
{
	FILE *fp = popen("route -n | grep eth0 | grep UG | awk '{print $2}'", "r");//打开管道，执行shell 命令
	char buffer[1024] = {0};
	int num=0;
	while (NULL != fgets(buffer, 1024, fp)) //逐行读取执行结果并打印
	{
		wipe_off_CRLF_inEnd(buffer);
		if(gw)
			strcpy(gw,buffer);
		num += 1;
	}
	pclose(fp); //关闭返回的文件指针，注意不是用fclose噢
	
	return num;
}
int getGWMAC_byCmd(char *gwip, char *gwmac)
{
	char cmd[128], gw[16], buffer[1024] = {0};
	int num=0;
	FILE *fp;

	if( getGW_byCmd(gw) <= 0 )
		return -1;
	sprintf(cmd, "arp -a | grep %s | awk '{print $4}'", gw);
	fp = popen(cmd, "r");
	while (NULL != fgets(buffer, 1024, fp)) //逐行读取执行结果并打印
	{
		wipe_off_CRLF_inEnd(buffer);
		if(gwmac)
			strcpy(gwmac, buffer);
		num += 1;
	}
	pclose(fp);

	if(gwip)
		strcpy(gwip, gw);

	return num;
}
int getDNS_byCmd(char *dns_1,char *dns_2)
{
	FILE *fp = popen("cat /etc/resolv.conf | grep nameserver | awk '{print $2}'", "r");//打开管道，执行shell 命令
	char buffer[1024] = {0};
	char dns[2][16] = {0};
	int num=0;
	while (NULL != fgets(buffer, 1024, fp)) //逐行读取执行结果并打印
	{
		wipe_off_CRLF_inEnd(buffer);
		strcpy(dns[num],buffer);
		num += 1;
		if(num>2)	break;
	}
	pclose(fp); //关闭返回的文件指针，注意不是用fclose噢
	if(dns_1)
		strcpy(dns_1,dns[0]);
	if(dns_2)
		strcpy(dns_2,dns[1]);
	
	return num;
}

int ip_check(char *ip)
{
	char *cip = ip;
	int icnt = 0, idot = 0, n;
	
	if(ip == NULL || strlen(ip) == 0)
		return 0;

	n = atoi(cip);
	if(n <= 0 || n > 255)
		return 0;
	
	while(*cip != '\0')
	{
		++icnt;
		if(*cip == '.')
		{
			if( *(cip+1) < '0' || *(cip+1) > '9' )
				return 0;
			n = atoi(cip+1);
			if(n < 0 || n > 255)
				return 0;
			++idot;
		}
		else
		{
			if( *cip < '0' || *cip > '9' )
				return 0;
		}
		++cip;
	}

	if(idot != 3 || icnt < 7 || icnt > 15)
		return 0;

	return 1;
}




int wf_udp_socket(int port)
{
	int sock = -1, ret = -1;
	struct sockaddr_in addr;

	memset(&addr, 0, sizeof(addr));
	
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock < 0)
		return sock;
	if(port <= 0)
		return sock;

	addr.sin_family =AF_INET;
	addr.sin_port=htons(port);
	//addr.sin_addr.s_addr=htonl(INADDR_ANY);

	ret = bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
	if(ret < 0)
	{
		close(sock);
		return ret;
	}

	return sock;
}

int wf_tcp_socket(int port)
{
	int sock = -1, ret = -1;
	struct sockaddr_in addr;

	memset(&addr, 0, sizeof(addr));

	sock = socket(AF_INET,SOCK_STREAM,0);
	if(sock < 0)
		return sock;
	if(port <= 0)
		return sock;

	addr.sin_family =AF_INET;
	addr.sin_port=htons(port);

	ret = bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
	if(ret < 0)
	{
		close(sock);
		return ret;
	}

	return sock;
}

int wf_accept(int sock, void *client_addr, int *addr_len)
{
	int client_sock = -1, len;
	struct sockaddr_in c_addr;
	len = sizeof(struct sockaddr_in);
	
	if(client_addr && addr_len)
		client_sock = accept(sock, (struct sockaddr *)client_addr, addr_len);
	else
		client_sock = accept(sock, (struct sockaddr *)&c_addr, &len);

	return client_sock;
}

int wf_connect(int clientSock, char *serverName, int serverPort)
{
	struct hostent *host = NULL;
	struct sockaddr_in addr;
	
	if( clientSock < 0 || serverName == NULL || serverPort <= 0 )
		return -1;
	memset(&addr, 0, sizeof(addr));
	
	if( ip_check(serverName) )
	{
		inet_aton(serverName, (struct in_addr *)&(addr.sin_addr));
	}
	else
	{
		host = gethostbyname(serverName);
		if(host == NULL)
			return -1;
		addr.sin_addr = *((struct in_addr *)(host->h_addr));
	}
	addr.sin_family =AF_INET;
	addr.sin_port = htons(serverPort);

	return connect(clientSock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
}

int wf_connect_socket(char *serverName, int serverPort, int clientPort)
{
	int sock = -1, ret = -1;
	
	sock = wf_tcp_socket(clientPort);
	if(sock < 0)
		return sock;
	
	if( wf_connect(sock, serverName, serverPort) != 0 )
	{
		close(sock);
		return ret;
	}

	return sock;
}

int wf_listen_socket(int port, int listen_num)
{
	int sock = -1, ret = -1;

	sock = wf_tcp_socket(port);
	if(sock < 0)
		return sock;

	ret = listen(sock, listen_num);
	if(ret < 0)
	{
		close(sock);
		return ret;
	}

	return sock;
}

int wf_send(int sock, unsigned char *buf, int total_len, int flag)
{
	int len=0, i=0, next=total_len;
	
	while(next > 0 && (len=send(sock, buf+i, next, flag)) != next)
	{
		if(len>0)
		{
			i += len;
			next -= len;
		}
		else if(len == 0)
			break;
		else if(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			continue;
		else
			return -1;
	}
	if(!i)
		return len;

	return i;
}

int wf_recv(int sock, unsigned char *buf, int total_len, int flag)
{
	int len=0, i=0, next=total_len;
	
	while(next > 0 && (len=recv(sock, buf+i, next, flag)) != next)
	{
		if(len>0)
		{
			i += len;
			next -= len;
		}
		else if(len == 0)
			break;
		else if(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			continue;
		else
			return -1;
	}

	return i;
}

// struct sockaddr_in *addr_to
int wf_sendto(int sock, unsigned char *buf, int total_len, int flag, void *addr_to)
{
	int len=0, i=0, next=total_len;
	
	while(next > 0 && (len=sendto(sock, buf+i, next, flag, (struct sockaddr *)addr_to,sizeof(struct sockaddr))) != next)
	{
		if(len>0)
		{
			i += len;
			next -= len;
		}
		else if(len == 0)
			break;
		else if(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			continue;
		else
			return -1;
	}
	if(!i)
		return len;

	return i;
}

int wf_sendto_ip(int sock, unsigned char *buf, int total_len, int flag, char *to_ip, int to_port)
{
	struct sockaddr_in addr_to;

	memset(&addr_to, 0, sizeof(addr_to));
	inet_aton(to_ip, (struct in_addr *)&(addr_to.sin_addr));
	addr_to.sin_family =AF_INET;
	addr_to.sin_port = htons(to_port);

	return wf_sendto(sock, buf, total_len, flag, &addr_to);
}

// struct sockaddr_in *addr_from
int wf_recvfrom(int sock, unsigned char *buf, int total_len, int flag, void *addr_from)
{
	int len=0;
	int sockaddr_len = sizeof(struct sockaddr_in);
	struct sockaddr_in addr;
	struct sockaddr *paddr = (struct sockaddr *)addr_from;

	if(addr_from == NULL)
	{
		memset(&addr, 0, sizeof(addr));
		paddr = (struct sockaddr *)&addr;
	}

	while(1)
	{
		len = recvfrom(sock, buf, total_len, flag, paddr, &sockaddr_len);

		if(len >= 0)
			break;
		else if(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			continue;
		else
			return -1;
	}

	return len;
}

int wf_recvfrom_ip(int sock, unsigned char *buf, int total_len, int flag, char *from_ip, int *from_port)
{
	int ret;
	struct sockaddr_in addr_from;

	ret = wf_recvfrom(sock, buf, total_len, flag, &addr_from);
	if(ret > 0)
	{
		if(from_ip)
			sprintf(from_ip, "%s", inet_ntoa(addr_from.sin_addr));
		if(from_port)
			*from_port = (int)ntohs(addr_from.sin_port);
	}

	return ret;
}

#if 0
void test()
{
	char buf[1024], buf_2[1024];
	
	//getHostIP(NULL, NULL, NULL, NULL);

	getGWMAC_byCmd(buf, buf_2);

	printf("%s  %s  \n");
}
void main()
{
	test();
}
#endif

