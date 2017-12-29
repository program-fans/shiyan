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
//#include <linux/route.h> // for struct rtentry
//#include <linux/rtnetlink.h>    //for rtnetlink   
#include <errno.h>

#include "wf_char.h"
#include "wf_misc.h"
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
/*
int get_netdev_gw(const char *ifname, char *gateway, unsigned int *gwaddr)
{
	int sock = -1;
	struct rtentry route;  // route item struct 

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if( sock < 0)
		return -1;

	if (ioctl(sock, SIOCRTMSG, &route) < 0){
		close(sock);
		return -1;
	}
	printf("gateway: %s\n",inet_ntoa(((struct sockaddr_in*)(&route.rt_gateway))->sin_addr));
	printf("dst: %s\n",inet_ntoa(((struct sockaddr_in*)(&route.rt_dst))->sin_addr));
	printf("dev: %s\n", route.rt_dev);
	printf("flags: %x\n", route.rt_flags);

	close(sock);
	return 0;
}
*/

int arp_ip2mac(char *ip, unsigned char *mac, unsigned int flag_mask)
{
	char linebuf[256] = {0}, ip_str[16] = {0}, mac_str[24] = {0}, mask_str[16] = {0}, dev_str[24] = {0};
	int hw_type = 0, flags = 0;
	int num = 0, select = 0;
	FILE *fp = NULL;

	fp = fopen("/proc/net/arp", "r");
	if(!fp)
		return -1;

	if(fgets(linebuf, sizeof(linebuf)-1, fp) == NULL){
		fclose(fp);
		return -2;
	}

	while(fgets(linebuf, sizeof(linebuf)-1, fp) != NULL){
		num = sscanf(linebuf, "%15s 0x%x 0x%x %23s %15s %23s\n",
			 ip_str, &hw_type, &flags, mac_str, mask_str, dev_str);
		if(num < 4)
			continue;
		if( !strcmp(ip_str, ip) && (!flag_mask || (flag_mask & flags)) ){
			select = 1;
			break;
		}
	}
	fclose(fp);

	if(select)
		return str2mac(mac_str, mac);
	return -3;
}

int arp_mac2ip(unsigned char *mac, char *ip, unsigned int flag_mask)
{
	char linebuf[256] = {0}, ip_str[16] = {0}, mac_str[24] = {0}, mask_str[16] = {0}, dev_str[24] = {0};
	unsigned char mac_hex[6] = {0};
	int hw_type = 0, flags = 0;
	int num = 0, select = 0;
	FILE *fp = NULL;

	fp = fopen("/proc/net/arp", "r");
	if(!fp)
		return -1;

	if(fgets(linebuf, sizeof(linebuf)-1, fp) == NULL){
		fclose(fp);
		return -2;
	}

	while(fgets(linebuf, sizeof(linebuf)-1, fp) != NULL){
		num = sscanf(linebuf, "%15s 0x%x 0x%x %23s %15s %23s\n",
			 ip_str, &hw_type, &flags, mac_str, mask_str, dev_str);
		if(num < 4)
			continue;
		str2mac(mac_str, mac_hex);
		if( !memcmp(mac_hex, mac, 6)  && (!flag_mask || (flag_mask & flags)) ){
			select = 1;
			break;
		}
	}
	fclose(fp);

	if(select)
		return sprintf(ip, "%s", ip_str);
	return -3;
}

/* from <linux/route.h>
#define RTF_UP          0x0001          // route usable                 
#define RTF_GATEWAY     0x0002          // destination is a gateway     
#define RTF_HOST        0x0004          // host entry (net otherwise)   
#define RTF_REINSTATE   0x0008          // reinstate route after tmout  
#define RTF_DYNAMIC     0x0010          // created dyn. (by redirect)   
#define RTF_MODIFIED    0x0020          // modified dyn. (by redirect)  
#define RTF_MTU         0x0040          // specific MTU for this route  
#define RTF_MSS         RTF_MTU         // Compatibility :-(            
#define RTF_WINDOW      0x0080          // per route window clamping    
#define RTF_IRTT        0x0100          // Initial round trip time      
#define RTF_REJECT      0x0200          // Reject route                 
*/
#define RT_FLAG_U		1
#define RT_FLAG_G		2
#define RT_FLAG_UG		3
#define RT_FLAG_H		4
struct route_t
{
	char iface[24];
	unsigned int destination;
	unsigned int gateway;
	unsigned int flags;
	unsigned int refcnt;
	unsigned int use;
	unsigned int metric;
	unsigned int mask;
	unsigned int mtu;
	unsigned int window;
	unsigned int irtt;
};

int get_host_gateway(char *gateway, unsigned int *gwaddr, char *ifname)
{
	FILE *fp = NULL;
	char linebuf[1024] = {0};
	int num = -1;
	struct route_t rt, *selct = NULL;
	struct in_addr gw;

	fp = fopen("/proc/net/route", "r");
	if(!fp)
		return -1;

	if(fgets(linebuf, sizeof(linebuf)-1, fp) == NULL){
		fclose(fp);
		return -2;
	}

	while(fgets(linebuf, sizeof(linebuf)-1, fp) != NULL)
	{
		memset(&rt, 0, sizeof(rt));
		num = sscanf(linebuf, "%23s %X %X %d %d %d %d %X %d %d %d\n",
			 rt.iface, &rt.destination, &rt.gateway, &rt.flags, &rt.refcnt, &rt.use, &rt.metric, &rt.mask, &rt.mtu, &rt.window, &rt.irtt);
		if(num < 4)
			continue;

		if(ifname){
			if(!strcmp(ifname, rt.iface) && (rt.flags & RT_FLAG_U) && (rt.flags & RT_FLAG_G)){
				selct = &rt;
				break;
			}
		}
		else{
			if((rt.flags & RT_FLAG_U) && (rt.flags & RT_FLAG_G)){
				selct = &rt;
				break;
			}
		}
	}
	fclose(fp);
	
	if(selct){
		if(gwaddr)
			*gwaddr = selct->gateway;
		if(gateway){
			gw.s_addr = selct->gateway;
			sprintf(gateway, "%s",(char *)inet_ntoa(gw));
		}
		return 0;
	}

	return -3;
}

/**************** rtnetlink ***************
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
	int rtLen, mark=0;
	
	rtMsg = (struct rtmsg *)NLMSG_DATA(nlHdr);   
	// If the route is not for AF_INET or does not belong to main routing table   
	//then return.    
	if(rtMsg->rtm_family != AF_INET)   
	//if((rtMsg->rtm_family != AF_INET) || (rtMsg->rtm_table != RT_TABLE_MAIN))   
		return 0;   
	printf("flags=%d \n", rtMsg->rtm_flags);
	rtAttr = (struct rtattr *)RTM_RTA(rtMsg);   
	rtLen = RTM_PAYLOAD(nlHdr);   
	for(;RTA_OK(rtAttr,rtLen);rtAttr = RTA_NEXT(rtAttr,rtLen))
	{
		switch(rtAttr->rta_type)
		{   
		case RTA_OIF:   // 4
			if_indextoname(*(int *)RTA_DATA(rtAttr), rtInfo->ifName);
			printf("RTA_OIF: %s \n", rtInfo->ifName);
			break;   
		case RTA_GATEWAY:   // 5
			rtInfo->gateWay = *(u_int *)RTA_DATA(rtAttr);
			printf("RTA_GATEWAY: 0x%x \n", rtInfo->gateWay);
			break;   
		case RTA_PREFSRC:  // 7  
			rtInfo->srcAddr = *(u_int *)RTA_DATA(rtAttr);
			printf("RTA_PREFSRC: 0x%x \n", rtInfo->srcAddr);
			break;   
		case RTA_DST:  // 1 
			rtInfo->dstAddr = *(u_int *)RTA_DATA(rtAttr);
			printf("RTA_DST: 0x%x \n", rtInfo->dstAddr);
			break;
		case RTA_MARK:  // 16 
			mark = *(u_int *)RTA_DATA(rtAttr);
			printf("RTA_MARK: 0x%x \n", mark);
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
	struct in_addr tmp_addr;

	for(; i<rt_num; i++)
	{
		printf("oif:%s  ",rtInfo[i].ifName);
		tmp_addr.s_addr = rtInfo[i].gateWay;
		printf("%s\n",(char *)inet_ntoa(tmp_addr));
		tmp_addr.s_addr = rtInfo[i].srcAddr;   
		printf("src:%s\n",(char *)inet_ntoa(tmp_addr));
		tmp_addr.s_addr = rtInfo[i].dstAddr;   
		printf("dst:%s\n",(char *)inet_ntoa(tmp_addr));

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
**************** rtnetlink ***************/

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
	static char ip_buf[16] = {0};

	if(!buff)
		buff = &ip_buf[0];
	a[0] = (unsigned char)(addr >> 24);
	a[1] = (unsigned char)(addr >> 16);
	a[2] = (unsigned char)(addr >> 8);
	a[3] = (unsigned char)(addr);
	sprintf(buff, "%d.%d.%d.%d", a[0], a[1], a[2], a[3]);
	return buff;
}

int get_dnsserver_by_resolv_conf(char *conf_file, char (*dnsserver)[16], int dnsserver_maxnum)
{
	FILE *fp = NULL;
	char linebuf[512] = {'\0'};
	char *p = NULL, tmp_ip[16] = {'\0'};
	int num = 0, count = 0;

	if(conf_file)
		fp = fopen(conf_file, "r");
	else
		fp = fopen("/etc/resolv.conf", "r");
	if(!fp)
		return -1;

	while(fgets(linebuf, sizeof(linebuf)-1, fp) != NULL)
	{
		if(linebuf[0] == '#')
			continue;
		p = strstr(linebuf, "nameserver");
		if(!p)
			continue;
		p += 10;
		memset(tmp_ip, 0, sizeof(tmp_ip));
		num = sscanf(p, "%15s\n", tmp_ip);
		if(num < 1)
			continue;
		if(!ip_check(tmp_ip))
			continue;

		strcpy(dnsserver[count], tmp_ip);
		++count;
		if(count >= dnsserver_maxnum)
			break;
	}
	fclose(fp);

	return count;
}

int lookup_etc_hosts(char *hostname, char *ip)
{
	FILE *fp = NULL;
	char linebuf[1024] = {'\0'};
	char tmp_name[256] = {'\0'}, tmp_ip[16] = {'\0'};
	int num = 0;

	if(!hostname)
		return -1;
	fp = fopen("/etc/hosts", "r");
	if(!fp)
		return -1;

	while(fgets(linebuf, sizeof(linebuf)-1, fp) != NULL)
	{
		memset(tmp_name, 0, sizeof(tmp_name));
		memset(tmp_ip, 0, sizeof(tmp_ip));
		num = sscanf(linebuf, "%15s %255s\n",tmp_ip, tmp_name);
		if(num < 2)
			continue;

		if(!strcmp(hostname, tmp_name)){
			if(ip)
				strcpy(ip, tmp_ip);
			fclose(fp);
			return 0;
		}
	}
	fclose(fp);
	return -2;
}

int dns_valid_check(char *dns)
{
	char *pch = dns, ch = '\0';
	int label_len = 0;
//	int label_count = 0;
	
	if(!dns || *dns == '\0' || *dns == '.')
		return 0;

	while(pch && *pch != '\0'){
		ch = *pch;
		if( (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || 
			(ch >= '0' && ch <= '9') || ch == '-' )
		{
			++label_len;
		}
		else if(ch == '.'){
			if(label_len <= 0 || label_len > 255)
				return 0;
//			else
//				++label_count;
//			if(label_count >= 255)
//				return 0;
			label_len = 0;
		}
		else
			return 0;
		++pch;
	}
	if(label_len <= 0 || label_len > 255)
		return 0;
//	if(label_num)
//		*label_num = label_count + 1;
	return 1;
}



struct dnsh{
	unsigned short id; // identification number

	unsigned char rd :1; // recursion desired
	unsigned char tc :1; // truncated message
	unsigned char aa :1; // authoritive answer
	unsigned char opcode :4; // purpose of message
	unsigned char qr :1; // query/response flag

	unsigned char rcode :4; // response code
	unsigned char cd :1; // checking disabled
	unsigned char ad :1; // authenticated data
	unsigned char z :1; // its z! reserved
	unsigned char ra :1; // recursion available

	unsigned short q_count; // number of question entries
	unsigned short ans_count; // number of answer entries
	unsigned short auth_count; // number of authority entries
	unsigned short add_count; // number of resource entries
};

struct dns_qtion{
	unsigned short qtype;
	unsigned short qclass;
};

struct dns_ation{
	unsigned short atype;
	unsigned short aclass;
	unsigned int ttl;
	unsigned short data_len;
};

int wf_pack_domain_to_buf(char *domain, int need_check, unsigned char *buf)
{
	char *find_dot = NULL, *p = (char *)(buf + 1);
	unsigned char *last_pad = buf;
	int label_len = 0, domain_len = 0;

	if(!domain || !buf)
		return -1;
	if(need_check && !dns_valid_check(domain))
		return -2;
	domain_len = strlen(domain);
	strcpy((char *)p, domain);
	buf[domain_len+2] = 0;
	while(1){
		find_dot = strchr(p, '.');
		if(!find_dot)
			break;
		label_len = find_dot - p;
		*last_pad = (unsigned char)label_len;
		last_pad = (unsigned char *)find_dot;
		p = (char *)last_pad + 1;
	}
	*last_pad = (unsigned char)strlen(p);

	return (domain_len + 2);
}

static unsigned int __wf_lookup_dns(char *domain, char *res_ip, char *set_dns_server, int timeout)
{
	char dnsserver[2][16] = {{'\0'}}, *use_dns_server = set_dns_server;
	struct sockaddr_in dns_server_addr;
	unsigned char buf[2048] = {0}, *p = &buf[0], *end_p = NULL;
	struct dnsh *p_dnsh = (struct dnsh *)&buf[0], *res_dnsh = (struct dnsh *)&buf[0];
	struct dns_qtion *p_qtion = NULL;
	struct dns_ation *p_ation = NULL;
	int len = 0, recv_len = 0, i = 0;
	struct timeval tv_out;
	int sock = -1;
	socklen_t sockaddr_len = sizeof(struct sockaddr_in);
	unsigned int *select_addr = NULL;
	unsigned int min_ttl = 0xFFFFFFFF, tmp_ttl = 0;
	struct in_addr target_ip;
	
	if(!dns_valid_check(domain))
		return 0;
	if(set_dns_server && !ip_check(set_dns_server))
		return 0;
	else{
		if(get_dnsserver_by_resolv_conf(NULL, dnsserver, 2) <= 0){
			if(get_host_gateway(NULL, &(dns_server_addr.sin_addr.s_addr), NULL) < 0)
				return 0;
		}
		else
			use_dns_server = &dnsserver[0][0];
	}

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(sock < 0)
		return 0;
	
	if(use_dns_server)
		inet_aton(use_dns_server, (struct in_addr *)&(dns_server_addr.sin_addr));
	dns_server_addr.sin_family =AF_INET;
	dns_server_addr.sin_port = htons(53);

	p_dnsh->id = htons((unsigned short)wf_getsys_uptime(NULL));
//	p_dnsh->id = 0;
	*(unsigned short *)((char *)&p_dnsh->id + sizeof(p_dnsh->id)) = htons(0x0100);
	p_dnsh->q_count = htons(1);
	p_dnsh->ans_count = 0;
	p_dnsh->auth_count = 0;
	p_dnsh->add_count = 0;
//	printf("p_dnsh->id = %4x \n", ntohs(p_dnsh->id));

	p += sizeof(struct dnsh);
	len = wf_pack_domain_to_buf(domain, 0, p);
	p_qtion = (struct dns_qtion *)(p + len);
	p_qtion->qtype = htons(1);
	p_qtion->qclass = htons(1);

	len += sizeof(struct dnsh) + sizeof(struct dns_qtion);

	if(timeout > 0)
        tv_out.tv_sec = timeout;
	else
		tv_out.tv_sec = 10;
	tv_out.tv_usec = 0;

	setsockopt(sock,SOL_SOCKET,SO_SNDTIMEO,&tv_out, sizeof(tv_out));
	setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,&tv_out, sizeof(tv_out));

	if(sendto(sock, buf, len, 0, (struct sockaddr *)&dns_server_addr,sizeof(struct sockaddr)) < 0){
		close(sock);
		return -3;
	}

	recv_len = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&dns_server_addr, &sockaddr_len);
	if(recv_len < len){
		close(sock);
		return 0;
	}
	close(sock);

	p = &buf[0] + len;
	end_p = &buf[0] + recv_len;
//	print_bytes(buf, recv_len);
//	printf("recv_len = %d \n", recv_len);
//	print_bytes(p, recv_len - len);
	for(i=0; i<(int)ntohs(res_dnsh->ans_count); i++){
		while(*p < 0xc0 && p < end_p)
			++p;
		if(p >= end_p)
			break;
		p += 2;
		p_ation = (struct dns_ation *)p;
//		printf("ntohs(p_ation->data_len) = %d \n", (int)ntohs(p_ation->data_len));
//		print_bytes(p, 10 + (int)ntohs(p_ation->data_len));
		if(p_ation->atype == htons(1)){
			tmp_ttl = (unsigned int)ntohl(p_ation->ttl);
			if(tmp_ttl < min_ttl){
				min_ttl = tmp_ttl;
				select_addr = (unsigned int *)(p + 10);
			}
		}
		
		p += 10 + (int)ntohs(p_ation->data_len);
		continue;
	}

	if(select_addr){
		if(res_ip){
			target_ip.s_addr = *select_addr;
			sprintf(res_ip, "%s",(char *)inet_ntoa(target_ip));
		}
		return *select_addr;
	}
	else
		return 0;
}
unsigned int wf_lookup_dns(char *domain, char *res_ip, char *set_dns_server, int timeout)
{
	struct in_addr target_ip;
	
	if(ip_check(domain)){
		inet_aton(domain, (struct in_addr *)&target_ip);
		strcpy(res_ip, domain);
		return target_ip.s_addr;
	}

	return __wf_lookup_dns(domain, res_ip, set_dns_server, timeout);
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

int wf_udp_getsockname(int sock, unsigned int *addr, int *port)
{
	struct sockaddr_in to_addr;
	struct sockaddr_in tmp_addr;
	int alen = sizeof(struct sockaddr_in), ret = 0;
	char buf[32];
	
	memset(&tmp_addr, 0, sizeof(tmp_addr));
	memset(&to_addr, 0, sizeof(to_addr));
	to_addr.sin_family =AF_INET;
	to_addr.sin_port=htons(1026);
	to_addr.sin_addr.s_addr=htonl(INADDR_ANY);
	sendto(sock, buf, sizeof(buf), 0, (struct sockaddr *)&to_addr,sizeof(struct sockaddr));
	ret = getsockname(sock, (struct sockaddr *)&tmp_addr, &alen);
	if(ret < 0)
		return ret;

	if(addr)
		*addr = tmp_addr.sin_addr.s_addr;
	if(port)
		*port = (int)ntohs(tmp_addr.sin_port);
	return ret;
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

int wf_tcp_socket(int port, int keepalive, char *if_name)
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
	if(if_name){
		ret = setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, if_name, strlen(if_name) + 1);
		if(ret < 0)
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

int wf_accept_ip(int sock, char *client_ip, int *client_port)
{
	int client_sock = -1;
	socklen_t len;
	struct sockaddr_in c_addr;
	len = sizeof(struct sockaddr_in);
	
	client_sock = accept(sock, (struct sockaddr *)&c_addr, &len);

	if(client_ip)
		sprintf(client_ip, "%s", inet_ntoa(c_addr.sin_addr));
	if(client_port)
		*client_port = (int)ntohs(c_addr.sin_port);

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

int wf_connect_socket(char *serverName, int serverPort, int clientPort, int keepalive, char *if_name)
{
	int sock = -1, ret = -1;
	
	sock = wf_tcp_socket(clientPort, keepalive, if_name);
	if(sock < 0)
		return sock;
	
	if( wf_connect(sock, serverName, serverPort) != 0 )
	{
		close(sock);
		return ret;
	}

	return sock;
}

int wf_listen_socket(int port, int listen_num, char *if_name)
{
	int sock = -1, ret = -1;

	sock = wf_tcp_socket(port, 0, if_name);
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
	if(len == next)
		i += len;

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
	if(len == next)
		i += len;
	
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
		else if(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR){
			//printf("recvfrom error: %s \n", strerror(errno));
			continue;
		}
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

