#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>  //for in_addr   
#include <linux/rtnetlink.h>    //for rtnetlink   
#include <errno.h>

#include "wf_char.h"
#include "wf_net.h"

int get_netdev_mac(const char *ifname, unsigned char *mac)
{
	int sock = -1;
	struct ifreq ifr;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if( sock < 0)
		return -1;

	ifr.ifr_addr.sa_family = AF_INET;
	strcpy(ifr.ifr_name, ifname);

	if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0){
		close(sock);
		return -1;
	}

	if(mac)
		memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	close(sock);

	return 0;
}

int get_netdev_ip(const char *ifname, char *ip)
{
	int sock = -1;
	struct ifreq ifr;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if( sock < 0)
		return -1;

	ifr.ifr_addr.sa_family = AF_INET;
	strcpy(ifr.ifr_name, ifname);

	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0){
		close(sock);
		return -1;
	}

	if(ip)
		sprintf(ip,"%s",inet_ntoa(((struct sockaddr_in*)&(ifr.ifr_addr))->sin_addr));
	close(sock);

	return 0;
}

int get_netdev_addr(const char *ifname, unsigned int *addr)
{
	int sock = -1;
	struct ifreq ifr;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if( sock < 0)
		return -1;

	ifr.ifr_addr.sa_family = AF_INET;
	strcpy(ifr.ifr_name, ifname);

	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0){
		close(sock);
		return -1;
	}

	if(addr)
		*addr = ((struct sockaddr_in*)&(ifr.ifr_addr))->sin_addr.s_addr;
	close(sock);

	return 0;
}

int get_netdev_dstip(const char *ifname, char *dstip)
{
	int sock = -1;
	struct ifreq ifr;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if( sock < 0)
		return -1;

	ifr.ifr_addr.sa_family = AF_INET;
	strcpy(ifr.ifr_name, ifname);

	if (ioctl(sock, SIOCGIFDSTADDR, &ifr) < 0){
		close(sock);
		return -1;
	}

	if(dstip)
		sprintf(dstip,"%s",inet_ntoa(((struct sockaddr_in*)&(ifr.ifr_dstaddr))->sin_addr));
	close(sock);

	return 0;
}

int get_netdev_dstaddr(const char *ifname, unsigned int *dstaddr)
{
	int sock = -1;
	struct ifreq ifr;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if( sock < 0)
		return -1;

	ifr.ifr_addr.sa_family = AF_INET;
	strcpy(ifr.ifr_name, ifname);

	if (ioctl(sock, SIOCGIFDSTADDR, &ifr) < 0){
		close(sock);
		return -1;
	}

	if(dstaddr)
		*dstaddr = ((struct sockaddr_in*)&(ifr.ifr_dstaddr))->sin_addr.s_addr;
	close(sock);

	return 0;
}

int get_netdev_broadip(const char *ifname, char *broadip)
{
	int sock = -1;
	struct ifreq ifr;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if( sock < 0)
		return -1;

	ifr.ifr_addr.sa_family = AF_INET;
	strcpy(ifr.ifr_name, ifname);

	if (ioctl(sock, SIOCGIFBRDADDR, &ifr) < 0){
		close(sock);
		return -1;
	}

	if(broadip)
		sprintf(broadip,"%s",inet_ntoa(((struct sockaddr_in*)&(ifr.ifr_broadaddr))->sin_addr));
	close(sock);

	return 0;
}

int get_netdev_broadaddr(const char *ifname, unsigned int *broadaddr)
{
	int sock = -1;
	struct ifreq ifr;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if( sock < 0)
		return -1;

	ifr.ifr_addr.sa_family = AF_INET;
	strcpy(ifr.ifr_name, ifname);

	if (ioctl(sock, SIOCGIFBRDADDR, &ifr) < 0){
		close(sock);
		return -1;
	}

	if(broadaddr)
		*broadaddr = ((struct sockaddr_in*)&(ifr.ifr_broadaddr))->sin_addr.s_addr;
	close(sock);

	return 0;
}

int get_netdev_mask(const char *ifname, char *maskstr, unsigned int *mask)
{
	int sock = -1;
	struct ifreq ifr;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if( sock < 0)
		return -1;

	ifr.ifr_addr.sa_family = AF_INET;
	strcpy(ifr.ifr_name, ifname);

	if (ioctl(sock, SIOCGIFNETMASK, &ifr) < 0){
		close(sock);
		return -1;
	}

	if(mask)
		*mask = ((struct sockaddr_in*)&(ifr.ifr_netmask))->sin_addr.s_addr;
	if(maskstr)
		sprintf(maskstr,"%s",inet_ntoa(((struct sockaddr_in*)&(ifr.ifr_netmask))->sin_addr));
	close(sock);

	return 0;
}

int get_netdev_mtu(const char *ifname)
{
	int sock = -1;
	int mtu = 0;
	struct ifreq ifr;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if( sock < 0)
		return -1;

	ifr.ifr_addr.sa_family = AF_INET;
	strcpy(ifr.ifr_name, ifname);

	if (ioctl(sock, SIOCGIFMTU, &ifr) < 0){
		close(sock);
		return -1;
	}

	mtu = ifr.ifr_mtu;
	close(sock);

	return mtu;
}

int get_netdev_ifindex(const char *ifname)
{
	int sock = -1;
	int ifindex = 0;
	struct ifreq ifr;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if( sock < 0)
		return -1;

	ifr.ifr_addr.sa_family = AF_INET;
	strcpy(ifr.ifr_name, ifname);

	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0){
		close(sock);
		return -1;
	}

	ifindex = ifr.ifr_ifindex;
	close(sock);

	return ifindex;
}


#define BUFSIZE 8192
struct route_info{   
	unsigned int dstAddr;   
	unsigned int srcAddr;   
	unsigned int gateWay;   
	char ifName[IF_NAMESIZE];   
};   
static int readNlSock(int sockFd, unsigned char *bufPtr, int seqNum, int pId)   
{   
	struct nlmsghdr *nlHdr;   
	int readLen = 0, msgLen = 0;   
	do{   
		//收到内核的应答   
		if((readLen = recv(sockFd, bufPtr, BUFSIZE - msgLen, 0)) < 0){   
			//perror("SOCK READ: ");   
			return -1;   
		}   

		nlHdr = (struct nlmsghdr *)bufPtr;   
		//检查header是否有效   
		if((NLMSG_OK(nlHdr, readLen) == 0) || (nlHdr->nlmsg_type == NLMSG_ERROR)){   
			//perror("Error in recieved packet");   
			return -1;   
		}   

		if(nlHdr->nlmsg_type == NLMSG_DONE){   
			break;   
		}   
		else{
			bufPtr += readLen;   
			msgLen += readLen;   
		}
		
		if((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0){
			break;   
		}   
	} while((nlHdr->nlmsg_seq != seqNum) || (nlHdr->nlmsg_pid != pId));   
	
	return msgLen;   
}   

//分析返回的路由信息   
static int parseRoutes(struct nlmsghdr *nlHdr, struct route_info *rtInfo)
{   
	struct rtmsg *rtMsg;   
	struct rtattr *rtAttr;   
	int rtLen;
	
	rtMsg = (struct rtmsg *)NLMSG_DATA(nlHdr);   
	// If the route is not for AF_INET or does not belong to main routing table   
	//then return.    
	if((rtMsg->rtm_family != AF_INET) || (rtMsg->rtm_table != RT_TABLE_MAIN))   
		return 0;   
//	printf("flags=%d \n", rtMsg->rtm_flags);
	rtAttr = (struct rtattr *)RTM_RTA(rtMsg);   
	rtLen = RTM_PAYLOAD(nlHdr);   
	for(;RTA_OK(rtAttr,rtLen);rtAttr = RTA_NEXT(rtAttr,rtLen))
	{
		switch(rtAttr->rta_type)
		{   
		case RTA_OIF:   // 4
			if_indextoname(*(int *)RTA_DATA(rtAttr), rtInfo->ifName);
//			printf("RTA_OIF: %s \n", rtInfo->ifName);
			break;   
		case RTA_GATEWAY:   // 5
			rtInfo->gateWay = *(u_int *)RTA_DATA(rtAttr);
//			printf("RTA_GATEWAY: 0x%x \n", rtInfo->gateWay);
			break;   
		case RTA_PREFSRC:  // 7  
			rtInfo->srcAddr = *(u_int *)RTA_DATA(rtAttr);
//			printf("RTA_PREFSRC: 0x%x \n", rtInfo->srcAddr);
			break;   
		case RTA_DST:  // 1 
			rtInfo->dstAddr = *(u_int *)RTA_DATA(rtAttr);
//			printf("RTA_DST: 0x%x \n", rtInfo->dstAddr);
			break;
		case RTA_TABLE:	// 15
		default:
			break;
		}
	}   
		
	return 1;
}   

static struct route_info *select_route(struct route_info *rtInfo, unsigned int rt_num, char *ifname)
{
	unsigned int i=0;
//	struct in_addr tmp_addr;

	for(; i<rt_num; i++)
	{
/*		printf("oif:%s  ",rtInfo[i].ifName);
		tmp_addr.s_addr = rtInfo[i].gateWay;
		printf("%s\n",(char *)inet_ntoa(tmp_addr));
		tmp_addr.s_addr = rtInfo[i].srcAddr;   
		printf("src:%s\n",(char *)inet_ntoa(tmp_addr));
		tmp_addr.s_addr = rtInfo[i].dstAddr;   
		printf("dst:%s\n",(char *)inet_ntoa(tmp_addr));
*/
		if(ifname){
			if(strcmp(rtInfo[i].ifName, ifname) == 0 && rtInfo[i].gateWay != 0)
				return &rtInfo[i];
		}
		if(rtInfo[i].dstAddr == 0 && rtInfo[i].gateWay != 0)
			return &rtInfo[i];
	}
	return NULL;
}

int get_host_gateway(char *gateway, unsigned int *gwaddr, char *ifname)
{   
	struct nlmsghdr *nlMsg;   
	struct rtmsg *rtMsg;   
	struct route_info rtInfo[8], *prt = NULL;
	int rt_idx = 0;
	struct in_addr gw;
	unsigned char *msgBuf;   
	int ret = 0;
	int sock, len, msgSeq = 0;   

	if((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0){   
		//perror("Socket Creation: ");   
		return -1;   
	}

	msgBuf = (unsigned char *)malloc(BUFSIZE);
	if(msgBuf == NULL){
		close(sock);
		return -1;
	}
	memset(msgBuf, 0, BUFSIZE);   
	nlMsg = (struct nlmsghdr *)msgBuf;   
	rtMsg = (struct rtmsg *)NLMSG_DATA(nlMsg);   
	nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)); // Length of message.   
	nlMsg->nlmsg_type = RTM_GETROUTE; // Get the routes from kernel routing table .   
	nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST; // The message is a request for dump.   
	nlMsg->nlmsg_seq = msgSeq++; // Sequence of the message packet.   
	nlMsg->nlmsg_pid = getpid(); // PID of process sending the request.   

	if(send(sock, nlMsg, nlMsg->nlmsg_len, 0) < 0){   
		//printf("Write To Socket Failed…\n");
		ret = -1;
		goto END;
	}   

	if((len = readNlSock(sock, msgBuf, msgSeq, getpid())) < 0){   
		//printf("Read From Socket Failed…\n");   
		ret = -1;
		goto END; 
	}   

	memset(rtInfo, 0, sizeof(rtInfo));   
	for(;NLMSG_OK(nlMsg,len);nlMsg = NLMSG_NEXT(nlMsg,len)){   
		if(parseRoutes(nlMsg, &rtInfo[rt_idx]))
			++rt_idx;
		if(rt_idx >= 8)
			break;
	}
	
	prt = select_route(rtInfo, rt_idx, ifname);
	if(prt){
		if(gwaddr)
			*gwaddr = prt->gateWay;
		if(gateway){
			gw.s_addr = prt->gateWay;
			sprintf(gateway, "%s",(char *)inet_ntoa(gw));
		}
	}
	else
		ret = -1;
END:
	free(msgBuf);   
	close(sock);   
	return ret;   
}   

int getHostIP_2(char *prior_if, char *ip, char *broadip, char *ifname, int *ifindex)
{
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
			//printf("ifname: %s\n", ifrp->ifr_name);
			//发送命令，获得网络接口的广播地址
			if (ioctl(sockfd, SIOCGIFBRDADDR, ifrp) == -1)	continue;
			if(broadip)	sprintf(broadip,"%s", inet_ntoa(((struct sockaddr_in*)&(ifrp->ifr_broadaddr))->sin_addr));

			//printf("broadip: %s \n", inet_ntoa(((struct sockaddr_in*)&(ifrp->ifr_broadaddr))->sin_addr));
			//if(ioctl(sockfd, SIOCGIFHWADDR, ifrp ) == 0){
			//	printf("mac: "MAC_FORMAT_STRING_CAPITAL"\n", MAC_FORMAT_SPLIT(ifrp->ifr_hwaddr.sa_data));
			//}
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
	int num=0;
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
	char dns[2][16] = {{'\0'}};
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

unsigned int ip_atoh(char *ip, unsigned int *addr)
{
	char *cip = ip;
	int icnt = 0, idot = 0, n;
	unsigned char a[4], *p = NULL;
	unsigned int ret = 0;
	
	if(ip == NULL || strlen(ip) == 0)
		return 0;

	n = atoi(cip);
	if(n <= 0 || n > 255)
		return 0;
	a[0] = (unsigned char)n;
	
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
			a[idot] = (unsigned char)n;
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
	p = (unsigned char *)&ret;
	*p++ = a[3];
	*p++ = a[2];
	*p++ = a[1];
	*p++ = a[0];
	if(addr)
		*addr = ret;
	
	return ret;
}

char *ip_htoa(unsigned int addr, char *buff)
{
	unsigned char a[4];

	a[0] = (unsigned char)(addr >> 24);
	a[1] = (unsigned char)(addr >> 16);
	a[2] = (unsigned char)(addr >> 8);
	a[3] = (unsigned char)(addr);
	sprintf(buff, "%d.%d.%d.%d", a[0], a[1], a[2], a[3]);
	return buff;
}


int setsock_broad(int sock, int on)
{
	int optval = on;
	return setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval));
}

int setsock_device(int sock, char *dev)
{
	return setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, dev, strlen(dev) + 1);
}

int setsock_multi(int sock, char *ip)
{
	struct ip_mreq mreq;

	mreq.imr_multiaddr.s_addr = inet_addr(ip);
	mreq.imr_interface.s_addr = htonl(INADDR_ANY);
	return setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq));
}

int setsock_reuse(int sock, int on)
{
	int optval = on;
	return setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
}

int setsock_rcvbuf(int sock, int size)
{
	int optval = size;
	return setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &optval, sizeof(optval));
}

int wf_udp_socket(int port, int is_broad, char *if_name)
{
	int optval = 1;
	int sock = -1, ret = -1;
	struct sockaddr_in addr;

	memset(&addr, 0, sizeof(addr));
	
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock < 0)
		return sock;

	if(is_broad){
		ret = setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &optval, sizeof (optval));
		if(ret)
			goto ERR;
	}
	if(if_name){
		ret = setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, if_name, strlen(if_name) + 1);
		if(ret < 0)
			goto ERR;
	}
	
	if(port <= 0)
		return sock;

	addr.sin_family =AF_INET;
	addr.sin_port=htons(port);
	//addr.sin_addr.s_addr=htonl(INADDR_ANY);

	ret = bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
	if(ret < 0)
	{
ERR:
		close(sock);
		return ret;
	}

	return sock;
}

int wf_tcp_socket(int port, int keepalive)
{
	int optval = 1;
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

	if(keepalive){
		ret = setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof (optval));
		if(ret)
			goto ERR;
	}

	ret = bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
	if(ret < 0)
	{
ERR:
		close(sock);
		return ret;
	}

	return sock;
}

int wf_gethostbyname(char *name, char *ip, unsigned int *addr)
{
	struct hostent *host = NULL;
	struct in_addr host_addr;
	char *ptr = name;

	if(strncmp(ptr, "http://", 7) == 0)
		ptr += 7;
	else if(strncmp(ptr, "https://", 8) == 0)
		ptr += 8;

	host = gethostbyname(ptr);
	if(!host)
		return -1;
	host_addr = *((struct in_addr *)(host->h_addr));
	//memcpy(&host_addr.s_addr, host->h_addr_list[0], sizeof(unsigned int));
	if(ip){
		inet_pton(host->h_addrtype, host->h_addr, ip);
		//sprintf(ip, "%s",(char *)inet_ntoa(host_addr));
	}
	if(addr)
		*addr = host_addr.s_addr;
	return 0;
}

int wf_accept(int sock, void *client_addr, int *addr_len)
{
	int client_sock = -1;
	socklen_t len;
	struct sockaddr_in c_addr;
	len = sizeof(struct sockaddr_in);
	
	if(client_addr && addr_len)
		client_sock = accept(sock, (struct sockaddr *)client_addr, (socklen_t *)addr_len);
	else
		client_sock = accept(sock, (struct sockaddr *)&c_addr, &len);

	return client_sock;
}

int wf_connect(int clientSock, char *serverName, int serverPort)
{
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
		if(wf_gethostbyname(serverName, NULL, &addr.sin_addr.s_addr) < 0)
			return -1;
	}
	addr.sin_family =AF_INET;
	addr.sin_port = htons(serverPort);

	return connect(clientSock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
}

int wf_connect_addr(int clientSock, unsigned int serverAddr, int serverPort)
{
	struct sockaddr_in addr;
	
	if( clientSock < 0 || serverAddr == 0 || serverPort <= 0 )
		return -1;
	memset(&addr, 0, sizeof(addr));
	addr.sin_addr.s_addr = serverAddr;
	addr.sin_family =AF_INET;
	addr.sin_port = htons(serverPort);

	return connect(clientSock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
}

int wf_connect_socket(char *serverName, int serverPort, int clientPort, int keepalive)
{
	int sock = -1, ret = -1;
	
	sock = wf_tcp_socket(clientPort, keepalive);
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

	sock = wf_tcp_socket(port, 0);
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
	int len=0;
	
	while(1)
	{
		len = sendto(sock, buf, total_len, flag, (struct sockaddr *)addr_to,sizeof(struct sockaddr));

		if(len >= 0)
			break;
		else if(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			continue;
		else
			return -1;
	}
	
	return len;
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
	socklen_t sockaddr_len = sizeof(struct sockaddr_in);
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

int udp_send(void *to_addr, int hport, unsigned char *buf, int len)
{
	int sock, ret;

	if( !to_addr || hport < 0 || !buf || len <= 0 )
		return -1;

	sock = wf_udp_socket(hport, 0, NULL);
	if(sock < 0)
		return sock;

	ret = wf_sendto(sock, buf, len, 0, to_addr);
	close(sock);
	return ret;
}

int udp_send_ip(char *ip, int hport, int dport, unsigned char *buf, int len)
{
	int sock, ret;

	if( !ip || hport < 0 || dport <=0 || dport >= 65535 || !buf || len <= 0 )
		return -1;

	sock = wf_udp_socket(hport, 0, NULL);
	if(sock < 0)
		return sock;

	ret = wf_sendto_ip(sock, buf, len, 0, ip, dport);
	close(sock);
	return ret;
}

int udp_recv(int hport, unsigned char *buf, int size, void *addr_from)
{
	int sock, ret;

	if( hport < 0 || !buf || size <= 0 )
		return -1;

	sock = wf_udp_socket(hport, 0, NULL);
	if(sock < 0)
		return sock;

	ret = wf_recvfrom(sock, buf, size, 0, addr_from);
	close(sock);
	return ret;
}

int udp_recv_ip(int hport, unsigned char *buf, int size, char *ip, int *sport)
{
	int sock, ret;

	if( hport < 0 || !buf || size <= 0 )
		return -1;

	sock = wf_udp_socket(hport, 0, NULL);
	if(sock < 0)
		return sock;

	ret = wf_recvfrom_ip(sock, buf, size, 0, ip, sport);
	close(sock);
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

