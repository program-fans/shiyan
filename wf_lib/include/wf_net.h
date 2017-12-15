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

extern int arp_ip2mac(char *ip, unsigned char *mac, unsigned int flag_mask);
extern int arp_mac2ip(unsigned char *mac, char *ip, unsigned int flag_mask);

extern int get_host_gateway(char *gateway, unsigned int *gwaddr, char *ifname);

/*
in: prior_if (prior interface)
out: ip  broadip  ifname  */
extern int getHostIP(char *prior_if, char *ip, char *broadip, char *ifname);
extern int getHostIP_2(char *prior_if, char *ip, char *broadip, char *ifname, int *ifindex);

extern int ip_check(char *ip);
extern unsigned int ip_atoh(char *ip, unsigned int *addr);
extern char *ip_htoa(unsigned int addr, char *buff);

extern int get_dnsserver_by_resolv_conf(char *conf_file, char (*dnsserver)[16], int dnsserver_maxnum);
extern int lookup_etc_hosts(char *hostname, char *ip);
extern int dns_valid_check(char *dns);

extern unsigned int wf_lookup_dns(char *domain, char *res_ip, char *set_dns_server, int timeout);

// ------------------------  wf socket --------------------------------------
#define wf_socket_error(errcode)	wf_std_error(errcode)

extern int setsock_broad(int sock, int on);

extern int setsock_device(int sock, char *dev);

extern int setsock_multi(int sock, char *ip);

extern int setsock_reuse(int sock, int on);

extern int setsock_rcvbuf(int sock, int size);

extern int wf_udp_socket(int port, int is_broad, char *if_name);

extern int wf_tcp_socket(int port, int keepalive, char *if_name);

extern int wf_gethostbyname(char *name, char *ip, unsigned int *addr);

extern int wf_accept(int sock, void *client_addr, int *addr_len);

extern int wf_accept_ip(int sock, char *client_ip, int *client_port);

extern int wf_connect(int clientSock, char *serverName, int serverPort);

extern int wf_connect_addr(int clientSock, unsigned int serverAddr, int serverPort);

extern int wf_connect_socket(char *serverName, int serverPort, int clientPort, int keepalive, char *if_name);

extern int wf_listen_socket(int port, int listen_num, char *if_name);

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

