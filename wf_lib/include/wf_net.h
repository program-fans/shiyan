#ifndef WF_NET_H_
#define WF_NET_H_

#define MAC_FORMAT_STRING "%02x-%02x-%02x-%02x-%02x-%02x"
#define MAC_FORMAT_STRING_CAPITAL   "%02X-%02X-%02X-%02X-%02X-%02X"
#define MAC_FORMAT_STRING_KERNEL	"%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_FORMAT_SPLIT(mac) (mac)[0],(mac)[1],(mac)[2],(mac)[3],(mac)[4],(mac)[5]

#ifndef WF_FD_SET
#define WF_FD_SET(fd, where, max_fd)	 { FD_SET(fd, where); if (fd > max_fd) max_fd = fd; }
#endif



extern int get_netdev_mac(const char *ifname, unsigned char *mac);
extern int get_netdev_ip(const char *ifname, char *ip);
extern int get_netdev_addr(const char * ifname, unsigned int *addr);
extern int get_netdev_dstip(const char * ifname, char *dstip);
extern int get_netdev_dstaddr(const char * ifname, unsigned int *dstaddr);
extern int get_netdev_broadip(const char * ifname, char *broadip);
extern int get_netdev_broadaddr(const char * ifname, unsigned int *broadaddr);
extern int get_netdev_mask(const char * ifname, char * maskstr, unsigned int * mask);
extern int get_netdev_mtu(const char * ifname);
extern int get_netdev_ifindex(const char * ifname);


extern int get_host_gateway(char *gateway, unsigned int *gwaddr, char *ifname);

/*
in: prior_if (prior interface)
out: ip  broadip  ifname  */
extern int getHostIP(char *prior_if, char *ip, char *broadip, char *ifname);
extern int getHostIP_2(char *prior_if, char *ip, char *broadip, char *ifname, int *ifindex);

// cmd: ifconfig  grep  sed  awk
extern int getIP_byCmd(char *ip);
// cmd: ifconfig  grep  awk
extern int getMAC_byCmd(char *mac);
// cmd: ifconfig  grep  sed  awk
extern int getMASK_byCmd(char *mask);
// cmd: route grep awk
extern int getGW_byCmd(char *gw);
// cmd: cat grep awk
extern int getDNS_byCmd(char *dns_1,char *dns_2);

extern int ip_check(char *ip);

// ------------------------  wf socket --------------------------------------
#define wf_socket_error(errcode)	wf_std_error(errcode)

extern int wf_udp_socket(int port, int is_broad, char *if_name);

extern int wf_tcp_socket(int port, int keepalive);

extern int wf_gethostbyname(char *name, char *ip, unsigned int *addr);

extern int wf_accept(int sock, void *client_addr, int *addr_len);

extern int wf_connect(int clientSock, char *serverName, int serverPort);

extern int wf_connect_addr(int clientSock, unsigned int serverAddr, int serverPort);

extern int wf_connect_socket(char *serverName, int serverPort, int clientPort, int keepalive);

extern int wf_listen_socket(int port, int listen_num);

extern int wf_send(int sock, unsigned char *buf, int total_len, int flag);

extern int wf_recv(int sock, unsigned char *buf, int total_len, int flag);

// struct sockaddr_in *addr_to
extern int wf_sendto(int sock, unsigned char *buf, int total_len, int flag, void *addr_to);

extern int wf_sendto_ip(int sock, unsigned char *buf, int total_len, int flag, char *to_ip, int to_port);

// struct sockaddr_in *addr_from
extern int wf_recvfrom(int sock, unsigned char *buf, int total_len, int flag, void *addr_from);

extern int wf_recvfrom_ip(int sock, unsigned char *buf, int total_len, int flag, char *from_ip, int *from_port);

extern int udp_send(void *to_addr, int hport, unsigned char *buf, int len);

extern int udp_send_ip(char *ip, int hport, int dport, unsigned char *buf, int len);

extern int udp_recv(int hport, unsigned char *buf, int size, void *addr_from);

extern int udp_recv_ip(int hport, unsigned char *buf, int size, char *ip, int *sport);

#endif

