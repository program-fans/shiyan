#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <netdb.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/epoll.h>

#include <fcntl.h>
#include <ctype.h>

#include <sys/time.h>

#include <dirent.h>
#include <sys/stat.h>

#include "libwf.h"

#define WFT_DEBUG(fmt, ...)	printf("[%s %d] "fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__);

static char print_name[32] = "wftool";
#define wfprintf(fmt, ...)	printf("[%s] "fmt, print_name, ##__VA_ARGS__);

#define dprintf(fmt, ...)	do { \
	if(debug)	printf(fmt, ##__VA_ARGS__);\
} while (0)

static int debug = 0;

int pipe_fd[2];
int init_pipe()
{
	int fl;
	
	if( pipe(pipe_fd)<0 )
		return -1;

	fl = fcntl(pipe_fd[0], F_GETFL, 0);
	if( fl == -1 )
		return -1;
	fcntl(pipe_fd[0], F_SETFL, fl |O_NONBLOCK);

	fl = fcntl(pipe_fd[1], F_GETFL, 0);
	if( fl == -1 )
		return -1;
	fcntl(pipe_fd[1], F_SETFL, fl |O_NONBLOCK);

	if( dup2(pipe_fd[0], STDIN_FILENO) < 0 )
		return -2;

	return 0;
}
void close_pipe()
{
	close(pipe_fd[0]);
	close(pipe_fd[1]);
}

static char asc_buf[4096] = {'\0'};
static struct threadpool* thread_pool = NULL;

void txt_usage()
{
	fprintf(stderr, "wftool txt usage: \n"
		"wftool ntorn [-s src-file] [-d dst-file] [--debug] \n"
		"wftool rnton [-s src-file] [-d dst-file] [--debug] \n"
		"wftool a1torn [-s src-file] [-d dst-file] [--debug] \n"
		);
}

struct txt_t
{
	char *sfile;
	FILE *fp_old;
	char *dfile;
	FILE *fp_new;
	unsigned int old_line;
	unsigned int new_line;
	unsigned int switch_line;
};

static int txt_ntorn(struct txt_t *txt)
{
	int line = 0;
	int tmp_len = 0;

	while( fgets(asc_buf, sizeof(asc_buf), txt->fp_old) != NULL )
	{
		++line;
		tmp_len = strlen(asc_buf);
		if( tmp_len >= 3 )
			dprintf("readline: %d len: %d [%d %d %d] \n", line, tmp_len, asc_buf[tmp_len-3], asc_buf[tmp_len-2], asc_buf[tmp_len-1]);
		else if( tmp_len >= 2 )
			dprintf("readline: %d len: %d [%d %d] \n", line, tmp_len, asc_buf[tmp_len-2], asc_buf[tmp_len-1]);
		else
			dprintf("readline: %d len: %d [%d] \n", line, tmp_len, asc_buf[tmp_len-1]);
		if( asc_buf[tmp_len-1] == '\n' && asc_buf[tmp_len-2] != '\r' )
		{
			asc_buf[tmp_len-1] = '\r';
			asc_buf[tmp_len] = '\n';
			asc_buf[tmp_len+1] = '\0';
			dprintf("writeline: %d len: %d \n", line, strlen(asc_buf));
			fputs(asc_buf, txt->fp_new);
			++txt->switch_line;
		}
		else
		{
			dprintf("writeline: %d len: %d \n", line, strlen(asc_buf)    );
			fputs(asc_buf, txt->fp_new);
		}
		memset(asc_buf, 0, sizeof(asc_buf));
	}

	txt->old_line = (unsigned int)line;
	txt->new_line = txt->old_line;
	return 0;
}

static int txt_rnton(struct txt_t *txt)
{
	int line = 0;
	int tmp_len = 0;
	
	while( fgets(asc_buf, sizeof(asc_buf), txt->fp_old) != NULL )
	{
		++line;
		tmp_len = strlen(asc_buf);
		if( tmp_len >= 3 )
			dprintf("readline: %d len: %d [%d %d %d] \n", line, tmp_len, asc_buf[tmp_len-3], asc_buf[tmp_len-2], asc_buf[tmp_len-1]);
		else if( tmp_len >= 2 )
			dprintf("readline: %d len: %d [%d %d] \n", line, tmp_len, asc_buf[tmp_len-2], asc_buf[tmp_len-1]);
		else
			dprintf("readline: %d len: %d [%d] \n", line, tmp_len, asc_buf[tmp_len-1]);
		if( asc_buf[tmp_len-1] == '\n' && asc_buf[tmp_len-2] == '\r' )
		{
			asc_buf[tmp_len-2] = '\n';
			asc_buf[tmp_len-1] = '\0';
			dprintf("writeline: %d len: %d \n", line, strlen(asc_buf));
			fputs(asc_buf, txt->fp_new);
			++txt->switch_line;
		}
		else
		{
			dprintf("writeline: %d len: %d \n", line, strlen(asc_buf)    );
			fputs(asc_buf, txt->fp_new);
		}
		memset(asc_buf, 0, sizeof(asc_buf));
	}

	txt->old_line = (unsigned int)line;
	txt->new_line = txt->old_line;
	return 0;
}

static int txt_a1torn(struct txt_t *txt)
{
// ´¦ÀíGBK ±àÂë
// 0xA1A1 ÎªÈ«½Ç¿Õ¸ñ
	int line = 0;
	int tmp_len = 0, i = 0, done = 0;
	unsigned char *pbyte = (unsigned char *)&asc_buf[0];

	while( fgets(asc_buf, sizeof(asc_buf), txt->fp_old) != NULL )
	{
		++line;
		tmp_len = strlen(asc_buf);

		done = 0;
		for(i=0; i<tmp_len; i++){
			if( pbyte[i] > 0x00 && pbyte[i] <= 0x7F ){			// ASCIIÂë
				dprintf("asc: %02X \n", pbyte[i]);
				continue;
			}
			else if( pbyte[i] >= 0x81 && pbyte[i] <= 0xFE ){			// ºº×Ö
				
				++i;
				if( pbyte[i] >= 0x40 && pbyte[i] <= 0x7E ){			// Ë«×Ö½Úºº×Ö
					dprintf("ch: %02X %02X \n", pbyte[i-1], pbyte[i]);
					continue;
				}
				else if( pbyte[i] >= 0x80 && pbyte[i] <= 0xFE ){		// Ë«×Ö½Úºº×Ö
					dprintf("ch: %02X %02X \n", pbyte[i-1], pbyte[i]);
					if(pbyte[i-1] == 0xA1 && pbyte[i] == 0xA1){
						pbyte[i-1] = '\r';
						pbyte[i] = '\n';
						++txt->new_line;
						done = 1;
					}
				}
				else if( pbyte[i] >= 0x30 && pbyte[i] <= 0x39 ){		// ËÄ×Ö½Úºº×Ö
					dprintf("ch: %02X %02X %02X %02X \n", pbyte[i-1], pbyte[i], pbyte[i+1], pbyte[i+2]);
					i += 2;
					continue;
				}
			}
		}
		fputs(asc_buf, txt->fp_new);
		if(done)
			++txt->switch_line;
		memset(asc_buf, 0, sizeof(asc_buf));
	}

	txt->old_line = (unsigned int)line;
	txt->new_line += txt->old_line;
	return 0;
}

static int txt_switch(struct txt_t *txt, int (*switch_call)(struct txt_t *txt))
{
	txt->fp_old = fopen(txt->sfile, "r");
	if(txt->fp_old == NULL){
		printf("open old file error: %s \n", txt->sfile);
		return -1;
	}
	txt->fp_new = fopen(txt->dfile, "w");
	if(txt->fp_new == NULL){
		printf("open new file error: %s \n", txt->dfile);
		fclose(txt->fp_old);
		return -2;
	}

	switch_call(txt);
	printf("switch OK : %u lines to %u lines   switch %u lines \n", txt->old_line, txt->new_line, txt->switch_line);

	fclose(txt->fp_old);
	fclose(txt->fp_new);

	return 0;
}

static int txt_cmd(int argc, char **argv, struct txt_t *txt)
{
	int i=1;
	
	while(argv[++i])
	{
		if( strcmp(argv[i], "-s") == 0 && argv[++i])
			txt->sfile = strdup(argv[i]);
		else if( strcmp(argv[i], "-d") == 0 && argv[++i])
			txt->dfile = strdup(argv[i]);
		else if( strcmp(argv[i], "--debug") == 0)
			debug = 1;
		else{
			printf("invalid param: %s \n", argv[i]);
			txt_usage();
			return -1;
		}
	}
}

int cmd_ntorn(int argc, char **argv)
{
	struct txt_t txt = {0};

	if( txt_cmd(argc, argv, &txt) < 0 )
		return -1;

	return txt_switch(&txt, txt_ntorn);
}

int cmd_rnton(int argc, char **argv)
{
	struct txt_t txt = {0};

	if( txt_cmd(argc, argv, &txt) < 0 )
		return -1;

	return txt_switch(&txt, txt_rnton);
}

int cmd_a1torn(int argc, char **argv)
{
	struct txt_t txt = {0};

	if( txt_cmd(argc, argv, &txt) < 0 )
		return -1;

	return txt_switch(&txt, txt_a1torn);
}


void udp_usage()
{
	fprintf(stderr, "wftool udp usage: \n"
		"wftool udp [cmd] [option] \n"
		"    cmd: send listen send-listen \n"
		"    --dev: bind network device \n"
		"    --ip \n"
		"    --hport \n"
		"    --dport \n"
		"    --msg: send data \n"
		"    --pkt: send packets. when cmd is listen: listen packets \n"
		"    --resp-pkt: listen packets \n"
		"    --no-wait \n"
		);
}

int udp_check_recv(int hport)
{
	if(hport <= 0 || hport > 65000){
		printf("invalid hport or not set: %d \n", hport);
		return 0;
	}
	return 1;
}
int udp_check_send(char *ip, int dport, int hport)
{
	if(!ip_check(ip)){
		printf("invalid ip or not set: %s \n", ip);
		return 0;
	}
	if(dport <= 0 || dport > 65000){
		printf("invalid dport or not set: %d \n", dport);
		return 0;
	}
	if(hport < 0 || hport > 65000){
		printf("invalid hport: %d \n", hport);
		return 0;
	}
	return 1;
}

enum TCP_UDP_ACT{
	TCP_UDP_ACT_SEND,
	TCP_UDP_ACT_LISTEN,
	UDP_ACT_SEND_LISTEN,
	TCP_ACT_CONNECT,
};

struct cmd_udp_t
{
	enum TCP_UDP_ACT action;
	int udp_sock, pkt_cnt, host_cnt;
	unsigned long bytes_cnt;
	
};
struct cmd_udp_t cmd_udp_globel;
void udp_exit_call(int sig)
{
	if(cmd_udp_globel.udp_sock > 0)
		close(cmd_udp_globel.udp_sock);
	if(cmd_udp_globel.action == TCP_UDP_ACT_LISTEN || cmd_udp_globel.action == UDP_ACT_SEND_LISTEN){
		printf("\nrecv finish: %lu bytes  %d packets  from %u hosts \n", 
			cmd_udp_globel.bytes_cnt, cmd_udp_globel.pkt_cnt, wf_get_kv_count());
		wf_kv_table_destory();
	}
	printf("exit...\n");
	exit(0);
}

int cmd_udp(int argc, char **argv)
{
	int i=1, ret=0;
	int hport = 0, dport = 0, sport = 0;
	int pkt = 1, resp_pkt = 1;
	enum TCP_UDP_ACT action = TCP_UDP_ACT_SEND;
	char *ip = NULL, *msg = NULL, *dev = NULL;
	char from_ip[16] = {0};
	int sock_flag = 0;

	++i;
	if( strcmp(argv[i], "send") == 0 )
		action = TCP_UDP_ACT_SEND;
	else if( strcmp(argv[i], "listen") == 0 )
		action = TCP_UDP_ACT_LISTEN;
	else if( strcmp(argv[i], "send-listen") == 0 )
		action = UDP_ACT_SEND_LISTEN;
	else
		--i;
	cmd_udp_globel.action = action;

	while(argv[++i])
	{
		if( strcmp(argv[i], "--ip") == 0 && argv[++i])
			ip = argv[i];
		else if( strcmp(argv[i], "--dev") == 0 && argv[++i])
			dev = argv[i];
		else if( strcmp(argv[i], "--msg") == 0 && argv[++i])
			msg = argv[i];
		else if( strcmp(argv[i], "--hport") == 0 && argv[++i])
			hport = atoi(argv[i]);
		else if( strcmp(argv[i], "--dport") == 0 && argv[++i])
			dport = atoi(argv[i]);
		else if( strcmp(argv[i], "--pkt") == 0 && argv[++i]){
			pkt = atoi(argv[i]);
			if(pkt<=0)
				pkt = 1;
		}
		else if( strcmp(argv[i], "--resp-pkt") == 0 && argv[++i]){
			resp_pkt = atoi(argv[i]);
			if(resp_pkt<=0)
				resp_pkt = 1;
		}
		else if( strcmp(argv[i], "--no-wait") == 0 )
			sock_flag = MSG_DONTWAIT;
		else{
			printf("invalid param: %s \n", argv[i]);
			return 0;
		}
	}

	if(action == TCP_UDP_ACT_LISTEN){
		if(resp_pkt == 1 && pkt > 1)
			resp_pkt = pkt;
		if( !udp_check_recv(hport) )
			return 0;
	}
	else if(action == TCP_UDP_ACT_SEND || action == UDP_ACT_SEND_LISTEN){
		if( !udp_check_send(ip, dport, hport) )
			return 0;
		if(!msg){
			printf("have no send data \n");
			return 0;
		}
	}
	
	cmd_udp_globel.udp_sock= wf_udp_socket(hport, 0, dev);
	if(cmd_udp_globel.udp_sock < 0){
		printf("error: %s \n", wf_socket_error(NULL));
		return 0;
	}

	wf_registe_exit_signal(udp_exit_call);

	if(action == TCP_UDP_ACT_SEND || action == UDP_ACT_SEND_LISTEN){
		while(pkt)
		{
			ret = wf_sendto_ip(cmd_udp_globel.udp_sock, (unsigned char *)msg, strlen(msg), 0,ip, dport);
			if(ret > 0)
				printf("send OK: %d bytes \n", ret);
			else
				printf("error: %s \n", wf_socket_error(NULL));
			--pkt;
		}
		
		if(action == TCP_UDP_ACT_SEND){
			close(cmd_udp_globel.udp_sock);
			return 0;
		}
	}

	while(resp_pkt)
	{
		memset(from_ip, 0, sizeof(from_ip));
		memset(asc_buf, 0, sizeof(asc_buf));
		ret = wf_recvfrom_ip(cmd_udp_globel.udp_sock, (unsigned char *)&asc_buf[0], sizeof(asc_buf), sock_flag, from_ip, &sport);
		if(ret > 0){
			++cmd_udp_globel.pkt_cnt; --resp_pkt; cmd_udp_globel.bytes_cnt += ret;
			wf_string_put_kv(from_ip, from_ip);
			printf("recv OK: %d bytes from %s:%d  [pkt id: %d]\n", ret, from_ip, sport, cmd_udp_globel.pkt_cnt);
			printf("\t%s \n", asc_buf);
		}
		else{
			printf("error: %s \n", wf_socket_error(NULL));
			//return;
		}
	}
	
	udp_exit_call(0);
	return 0;
}

void tcp_usage()
{
	fprintf(stderr, "wftool tcp usage: \n"
		"wftool tcp [cmd] [option] \n"
		"    cmd: send listen connect \n"
		"    --dev: bind network device \n"
		"    --ip \n"
		"    --hport \n"
		"    --dport \n"
		"    --msg: send data \n"
		"    --pkt: send packets. \n"
		"    --listen_num: listen the number of socket \n"
		"    --keepalive \n"
		"    --no-wait \n"
		);
}

struct tcp_client
{
	struct list_head node;
	int sock;
	char client_ip[16];
	int client_port;
};
struct cmd_tcp_t
{
	enum TCP_UDP_ACT action;
	int tcp_sock;
	int epfd;
	unsigned long bytes_cnt;
	int sock_flag;
	struct list_head client_list;
	int client_cur_num;
	int accept_num;
	int client_total_num;
};
struct cmd_tcp_t cmd_tcp_globel;

static struct tcp_client *create_tcp_client(int client_sock, char *client_ip, int client_port)
{
	struct tcp_client *client = (struct tcp_client *)malloc(sizeof(struct tcp_client));
	
	if(!client){
		printf("error: %s \n", wf_socket_error(NULL));
		return NULL;
	}
	
	client->sock = client_sock;
	strcpy(client->client_ip, client_ip);
	client->client_port = client_port;
	INIT_LIST_HEAD(&(client->node));
	return client;
	
}
static void remove_tcp_client(struct tcp_client *client)
{
	struct epoll_event ep_event = {0};

	printf("remove  client %s:%d \n", client->client_ip, client->client_port);
	list_del(&(client->node));
	--cmd_tcp_globel.client_cur_num;
	ep_event.events = EPOLLIN | EPOLLOUT | EPOLLERR;
	ep_event.data.fd = client->sock;
	epoll_ctl(cmd_tcp_globel.epfd, EPOLL_CTL_DEL, client->sock, &ep_event);
	close(client->sock);
	free(client);
}
static int add_tcp_client(struct tcp_client *client)
{
	struct epoll_event ep_event = {0};
	
	list_add(&(client->node), &cmd_tcp_globel.client_list);
	++cmd_tcp_globel.client_cur_num;
	++cmd_tcp_globel.client_total_num;

	ep_event.events = EPOLLIN | EPOLLOUT | EPOLLERR;
	ep_event.data.fd = client->sock;
	ep_event.data.ptr = client;
	if(epoll_ctl(cmd_tcp_globel.epfd, EPOLL_CTL_ADD, client->sock, &ep_event) < 0){
		printf("error: %s \n", wf_socket_error(NULL));
		remove_tcp_client(client);
		return -1;
	}
	printf("add  client %s:%d  sock fd: %d \n", client->client_ip, client->client_port, client->sock);
	
	return 0;
}
static void remove_all_tcp_client()
{
	struct tcp_client *pos, *n;
	struct epoll_event ep_event = {0};

	if(list_empty(&cmd_tcp_globel.client_list)){
		cmd_tcp_globel.client_cur_num = 0;
		return;
	}
	
	list_for_each_entry_safe(pos, n, &cmd_tcp_globel.client_list, node){
		ep_event.events = EPOLLIN | EPOLLOUT | EPOLLERR;
		ep_event.data.fd = pos->sock;
		epoll_ctl(cmd_tcp_globel.epfd, EPOLL_CTL_DEL, pos->sock, &ep_event);
		close(pos->sock);
		free(pos);
	}

	cmd_tcp_globel.client_cur_num = 0;
	INIT_LIST_HEAD(&cmd_tcp_globel.client_list);
}

void tcp_exit_call(int sig)
{
	if(cmd_tcp_globel.tcp_sock> 0)
		close(cmd_tcp_globel.tcp_sock);
	
	if(cmd_tcp_globel.action == TCP_UDP_ACT_LISTEN){
		if(cmd_tcp_globel.epfd > 0)
			close(cmd_tcp_globel.epfd);
		remove_all_tcp_client();
		printf("\nrecv finish: %lu bytes   from %u hosts  accept %u times\n", cmd_tcp_globel.bytes_cnt, wf_get_kv_count(), 
			cmd_tcp_globel.accept_num);
		wf_kv_table_destory();
	}
	
	printf("exit...\n");
	exit(0);
}

int tcp_listen(int listen_num)
{
	int client_sock = -1;
	int ret = 0, event_num = 0, i = 0;
	struct epoll_event ep_event;
	struct epoll_event event_list[48];
	struct tcp_client *client = NULL;
	char client_ip[16] = {0};
	int client_port = 0;
	
	cmd_tcp_globel.epfd = epoll_create(listen_num+1);
	if(cmd_tcp_globel.epfd < 0)
		goto EPOLL_ERR;

	ep_event.events = EPOLLIN | EPOLLERR;
	ep_event.data.fd = cmd_tcp_globel.tcp_sock;
	ret = epoll_ctl(cmd_tcp_globel.epfd, EPOLL_CTL_ADD, cmd_tcp_globel.tcp_sock, &ep_event);
	if(ret < 0)
		goto EPOLL_ERR;

	while(1){
		event_num = epoll_wait(cmd_tcp_globel.epfd, event_list, 48, 1000);
		if(event_num < 0){
			if(errno == EINTR){
				continue;
			}
			goto EPOLL_ERR;
		}

		for(i=0; i<event_num; i++){
			if(event_list[i].events && EPOLLIN){
				if(event_list[i].data.fd == cmd_tcp_globel.tcp_sock){
					client_sock = wf_accept_ip(event_list[i].data.fd, client_ip, &client_port);
					if(client_sock < 0){
						printf("error: %s \n", wf_socket_error(NULL));
						continue;
					}

					printf("accept  client %s:%d \n", client_ip, client_port);
					++cmd_tcp_globel.accept_num;
					wf_string_put_kv(client_ip, client_ip);
					client = create_tcp_client(client_sock, client_ip, client_port);
					if(!client)
						continue;
					if(add_tcp_client(client) < 0){
						printf("add client %s:%d failed \n", client_ip, client_port);
						continue;
					}
				}
				else{
					client = (struct tcp_client *)event_list[i].data.ptr;
					if(!client)
						continue;
					ret = wf_recv(client->sock, (unsigned char *)asc_buf, sizeof(asc_buf), cmd_tcp_globel.sock_flag);
					if(ret > 0){
						cmd_tcp_globel.bytes_cnt += ret;
						printf("recv OK: %d bytes from %s:%d \n", ret, client->client_ip, client->client_port);
						printf("\t%s \n", asc_buf);
					}
					else{
						if(ret == 0)
							printf("client [%s:%d] disconnect \n", client->client_ip, client->client_port);
						else
							printf("error: %s \n", wf_socket_error(NULL));
						remove_tcp_client(client);
					}
				}
			}
			else if(event_list[i].events && EPOLLERR){
				if(event_list[i].data.fd == cmd_tcp_globel.tcp_sock){
					printf("listen socket happen error \n");
					goto EPOLL_ERR;
				}
				else{
					client = (struct tcp_client *)event_list[i].data.ptr;
					if(!client)
						continue;
					printf("socket of client [%s:%d] happen error \n", client->client_ip, client->client_port);
					remove_tcp_client(client);
				}
			}
		}
	}
	

EPOLL_ERR:
	printf("error: %s \n", wf_socket_error(NULL));
	
	return -1;
}

int cmd_tcp(int argc, char **argv)
{
	int i=1, ret=0;
	int hport = 0, dport = 0, sport = 0;
	int pkt = 1;
	enum TCP_UDP_ACT action = TCP_UDP_ACT_SEND;
	char *ip = NULL, *msg = NULL, *dev = NULL;
	char from_ip[16] = {0};
	int keepalive = 0, listen_num = 64;

	++i;
	if( strcmp(argv[i], "send") == 0 )
		action = TCP_UDP_ACT_SEND;
	else if( strcmp(argv[i], "listen") == 0 )
		action = TCP_UDP_ACT_LISTEN;
	else if( strcmp(argv[i], "connect") == 0 )
		action = TCP_ACT_CONNECT;
	else
		--i;
	cmd_tcp_globel.action = action;

	while(argv[++i])
	{
		if( strcmp(argv[i], "--ip") == 0 && argv[++i])
			ip = argv[i];
		else if( strcmp(argv[i], "--dev") == 0 && argv[++i])
			dev = argv[i];
		else if( strcmp(argv[i], "--msg") == 0 && argv[++i])
			msg = argv[i];
		else if( strcmp(argv[i], "--hport") == 0 && argv[++i])
			hport = atoi(argv[i]);
		else if( strcmp(argv[i], "--dport") == 0 && argv[++i])
			dport = atoi(argv[i]);
		else if( strcmp(argv[i], "--pkt") == 0 && argv[++i]){
			pkt = atoi(argv[i]);
			if(pkt<=0)
				pkt = 1;
		}
		else if( strcmp(argv[i], "--listen_num") == 0 && argv[++i]){
			listen_num = atoi(argv[i]);
			if(listen_num<=0)
				listen_num = 1;
		}
		else if( strcmp(argv[i], "--no-wait") == 0 )
			cmd_tcp_globel.sock_flag = MSG_DONTWAIT;
		else if( strcmp(argv[i], "--keepalive") == 0 )
			keepalive = 1;
		else{
			printf("invalid param: %s \n", argv[i]);
			return 0;
		}
	}

	if(action == TCP_UDP_ACT_LISTEN){
		if( !udp_check_recv(hport) )
			return 0;
	}
	else if(action == TCP_UDP_ACT_SEND || action == TCP_ACT_CONNECT){
		if( !udp_check_send(ip, dport, hport) )
			return 0;
		if(action == TCP_UDP_ACT_SEND && !msg){
			printf("have no send data \n");
			return 0;
		}
	}
	INIT_LIST_HEAD(&cmd_tcp_globel.client_list);

	if(action == TCP_UDP_ACT_SEND ||action == TCP_ACT_CONNECT){
		cmd_tcp_globel.tcp_sock = wf_connect_socket(ip, dport, hport, keepalive, dev);
		if(cmd_tcp_globel.tcp_sock >= 0){
			printf("connect %s:%d OK! \n", ip, dport);
			if(action == TCP_ACT_CONNECT){
				if(keepalive){
					wf_registe_exit_signal(tcp_exit_call);
					while(1);
				}
				else
					goto END;
			}
		}
	}
	else{
		cmd_tcp_globel.tcp_sock = wf_listen_socket(hport, listen_num, dev);
	}
	
	if(cmd_tcp_globel.tcp_sock < 0){
		printf("error: %s \n", wf_socket_error(NULL));
		return 0;
	}

	wf_registe_exit_signal(tcp_exit_call);

	if(action == TCP_UDP_ACT_SEND){
		while(pkt)
		{
			ret = wf_send(cmd_tcp_globel.tcp_sock, (unsigned char *)msg, strlen(msg), cmd_tcp_globel.sock_flag);
			if(ret > 0)
				printf("send OK: %d bytes \n", ret);
			else
				printf("error: %s \n", wf_socket_error(NULL));
			--pkt;
		}
	}
	else if(action == TCP_UDP_ACT_LISTEN)
		tcp_listen(listen_num);
	
END:
	tcp_exit_call(0);
	return 0;
}

void gethost_usage()
{
	fprintf(stderr, "wftool gethost usage: \n"
		"wftool gethost [url] [url] [...] \n"
		);
}

struct gethost_job
{
	char *name;
	int id;
};
struct gethost_stat
{
	int ok_cnt, fail_cnt, valid_cnt, all_cnt;
	long start, end;
	pthread_mutex_t lock; 
};
struct gethost_stat cmd_gethost_stat;
int gethost_job(void *arg)
{
	int ret=0;
	struct hostent *hptr;
	char *ptr, **pptr;
	char str[32];
	struct gethost_job *name = (struct gethost_job *)arg;

	if((hptr = gethostbyname(name->name)) == NULL)
	{
		pthread_mutex_lock(&(cmd_gethost_stat.lock));
		++cmd_gethost_stat.fail_cnt;
		pthread_mutex_unlock(&(cmd_gethost_stat.lock));
		printf("error url[%d]: %s \n", name->id, name->name);
		ret = -1;
		goto JOG_END;
	}

	pthread_mutex_lock(&(cmd_gethost_stat.lock));
	++cmd_gethost_stat.ok_cnt;
	pthread_mutex_unlock(&(cmd_gethost_stat.lock));
	
	printf("url[%d]: %s \n", name->id, name->name);
	printf("host: %s \n", hptr->h_name);
	
	for(pptr = hptr->h_aliases; *pptr != NULL; pptr++)
		printf("\talias: %s \n", *pptr);

	switch(hptr->h_addrtype)
	{
		case AF_INET:
		case AF_INET6:
			pptr = hptr->h_addr_list;
			inet_ntop(hptr->h_addrtype, hptr->h_addr, str, sizeof(str));
			printf("\tfirst ip: %s \n", str);
			for(; *pptr != NULL; pptr++){
				inet_ntop(hptr->h_addrtype, *pptr, str, sizeof(str));
				printf("\tip: %s \n", str);
			}
			break;
		default:
			printf("\terror ip: unknown address type \n");
			break;
	}

JOG_END:
	free(name->name);
	free(name);
	return ret;
}

void gethost_result()
{
	cmd_gethost_stat.end = wf_getsys_uptime(NULL);
	
	printf("[stat] all: %d  valid: %d  ok: %d  fail: %d   [time: %ld s]\n", 
		cmd_gethost_stat.all_cnt, cmd_gethost_stat.valid_cnt,
		cmd_gethost_stat.ok_cnt, cmd_gethost_stat.fail_cnt,
		cmd_gethost_stat.end-cmd_gethost_stat.start);
	
	if(cmd_gethost_stat.valid_cnt == cmd_gethost_stat.ok_cnt + cmd_gethost_stat.fail_cnt)
		printf("[stat] finish \n");
	else
		printf("[stat] not finish \n");
}

void gethost_exit()
{
	threadpool_destroy(thread_pool);
	gethost_result();
	exit(0);
}

int cmd_gethost(int argc, char **argv)
{
	int i = 1;
	char *arg;
	
	struct gethost_job *pjob = NULL;

	if ( pthread_mutex_init(&(cmd_gethost_stat.lock), NULL) ){
		printf("error: mutex init \n");
		return -1;
	}
	if( NULL == (thread_pool = threadpool_init(15, 100)) ){
		printf("error: thread pool init \n");
		return -2;
	}

	wf_registe_exit_signal(gethost_exit);
	cmd_gethost_stat.start = wf_getsys_uptime(NULL);
	while(1)
	{
		if(argv[2])
			arg = argv[++i];
		else{
			memset(asc_buf, 0, sizeof(asc_buf));
			arg = fgets(asc_buf, sizeof(asc_buf), stdin);
		}
		if( !arg )
			break;
		++cmd_gethost_stat.all_cnt;
		wipe_off_CRLF_inEnd(arg);
		if(0 == strlen(arg))
			continue;
		++cmd_gethost_stat.valid_cnt;

		pjob = (struct gethost_job *)malloc(sizeof(struct gethost_job));
		if(pjob){
			pjob->id = cmd_gethost_stat.all_cnt;
			pjob->name = strdup(arg);
			if(!pjob->name){
				free(pjob);
				goto fail_done;
			}
		}
		else{
			goto fail_done;
		}
		
		
		if( threadpool_add_job(thread_pool, gethost_job, pjob, NULL) < 0)
			goto fail_done;
		else
			continue;

	fail_done:
		pthread_mutex_lock(&(cmd_gethost_stat.lock));
		++cmd_gethost_stat.fail_cnt;
		pthread_mutex_unlock(&(cmd_gethost_stat.lock));
		continue;
	}
	printf(">>>>>>>>>>>>>>>>>>>>>>> add job num: %d \n", cmd_gethost_stat.all_cnt);

	while(cmd_gethost_stat.valid_cnt != cmd_gethost_stat.ok_cnt + cmd_gethost_stat.fail_cnt)	sleep(1);
	threadpool_destroy(thread_pool);
	gethost_result();
	
	return 0;
}

void asc_usage()
{
	fprintf(stderr, "wftool asc usage: \n"
		"wftool asc [-d] [-x] [-X] [-c] [-s] [--all] [--stage] \n"
		);
}

int cmd_asc(int argc, char **argv)
{
	char asc_note[33][128] = {
		"NUL(null)",
		"SOH(start of headline)",
		"STX (start of text)",
		"ETX (end of text)",
		"EOT (end of transmission)",
		"ENQ (enquiry)",
		"ACK (acknowledge)",
		"BEL (bell)",
		"BS (backspace)",
		"HT (horizontal tab)",
		"LF (NL line feed, new line)",
		"VT (vertical tab)",
		"FF (NP form feed, new page)",
		"CR (carriage return)",
		"SO (shift out)",
		"SI (shift in)",
		"DLE (data link escape)",
		"DC1 (device control 1)",
		"DC2 (device control 2)",
		"DC3 (device control 3)",
		"DC4 (device control 4)",
		"NAK (negative acknowledge)",
		"SYN (synchronous idle)",
		"ETB (end of trans. block)",
		"CAN (cancel)",
		"EM (end of medium)",
		"SUB (substitute)",
		"ESC (escape)",
		"FS (file separator)",
		"GS (group separator)",
		"RS (record separator)",
		"US (unit separator)",
		"(space)"
	};
	char asc127_note[128]="DEL(delete)";
	int i=1, j=0;
	int asc_d=0;
	char *asc_s = asc_buf;
	int s_index = -1;
	int stage = 0, start = 0, end = 127;

	while(argv[++i])
	{
		if( strcmp(argv[i], "-d") == 0 && argv[++i]){
			sscanf(argv[i], "%d", &asc_d);
			asc_s[++s_index] = (char)asc_d;
		}
		else if( strcmp(argv[i], "-X") == 0 && argv[++i]){
			sscanf(argv[i], "%X", &asc_d);
			asc_s[++s_index] = (char)asc_d;
		}
		else if( strcmp(argv[i], "-x") == 0 && argv[++i]){
			sscanf(argv[i], "%x", &asc_d);
			asc_s[++s_index] = (char)asc_d;
		}
		else if( strcmp(argv[i], "-c") == 0 && argv[++i])
			sscanf(argv[i], "%c", &asc_s[++s_index]);
		else if( strcmp(argv[i], "-s") == 0 && argv[++i]){
			strcpy(&asc_s[++s_index], argv[i]);
			j = strlen(&asc_s[s_index])-1;
			s_index = j>0 ? s_index + j : s_index;
		}
		else if( strcmp(argv[i], "--all") == 0 )
			stage = 1;
		else if( strcmp(argv[i], "--stage") == 0 && argv[++i]){
			if( strstr(argv[i], "-") )
				sscanf(argv[i], "%d-%d", &start, &end);
			else if( strstr(argv[i], ":") )
				sscanf(argv[i], "%d:%d", &start, &end);
			if(start < 0)	start = 0;
			if(end > 127)	end = 127;
			if(start > end){
				stage = start;
				start = end;
				end = stage;
			}
			stage = 1;
		}
		else{
			printf("invalid param: %s \n", argv[i]);
			return -1;
		}
	}

	printf("dec\thex\tchar\tnote \n");

	if(s_index >= 0)
	{
		for(j=0; j<=s_index; j++){
			if(asc_s[j] < 0 || asc_s[j] > 127){
				printf("invaild asc \n");
				continue;
			}
			if(asc_s[j] >=0 && asc_s[j] <= 32)
				printf("%d\t0x%02X\t\t%s \n", (int)asc_s[j], asc_s[j], asc_note[(int)asc_s[j]]);
			else if( asc_s[j] == 127 )
				printf("%d\t0x%02X\t\t%s \n", (int)asc_s[j], asc_s[j], asc127_note);
			else
				printf("%d\t0x%02X\t%c \n", (int)asc_s[j], asc_s[j], asc_s[j]);
		}
	}

	if(stage)
	{
		printf("----------------------------------------\n");
		for(j=start; j<=end; j++){
			if(j >=0 && j <= 32)
				printf("%d\t0x%02X\t\t%s \n", j, j, asc_note[j]);
			else if( j == 127 )
				printf("%d\t0x%02X\t\t%s \n", j, j, asc127_note);
			else
				printf("%d\t0x%02X\t%c \n", j, j, (char)j);
		}
		printf("----------------------------------------\n");
	}

	return 0;
}


void wol_usage()
{
	fprintf(stderr, "wftool wol usage: \n"
		"wftool wol [-i ip-address] [-p port] [-o interface-dev-name] [--passwd xx-xx-xx-xx-xx-xx] mac \n"
		);
}

int cmd_wol(int argc, char **argv)
{
	int i=1, ret=0;
	int port = 9;
	char *ip = NULL, *pmac = NULL, *if_name = NULL;
	char broad[16] = "255.255.255.255";
	unsigned char mac[6] = {0}, pwd[6] = {0};
	unsigned char data[108] = {0};
	int sock, len=102, have_pwd = 0;

	while(argv[++i])
	{
		if( strcmp(argv[i], "-i") == 0 && argv[++i]){
			ip = argv[i];
			if(!ip_check(ip)){
				printf("invalid ip: %s \n", argv[i]);
				return -1;
			}
		}
		else if( strcmp(argv[i], "-p") == 0 && argv[++i]){
			port = atoi(argv[i]);
			if(port <= 0 || port >= 65535){
				printf("invalid port: %s \n", argv[i]);
				return -1;
			}
		}
		else if( strcmp(argv[i], "-o") == 0 && argv[++i]){
			if_name = argv[i];
		}
		else if( strcmp(argv[i], "--passwd") == 0 && argv[++i]){
			if( str2mac(argv[i], pwd) < 0){
				printf("invalid pwd: %s \n", argv[i]);
				return -1;
			}
		}
		else{
			pmac = argv[i];
			if( str2mac(argv[i], mac) < 0){
				printf("invalid mac: %s \n", argv[i]);
				return -1;
			}
		}
	}

	memset(data, 0xff, 6);
	for(i=6; i<102; i+=6){
		memcpy(&data[i], mac, 6);
	}
	if(have_pwd){
		memcpy(&data[102], pwd, 6);
		len = 108;
	}

	if(NULL == ip)
		ip = &broad[0];

	ret = sock = wf_udp_socket(0, 1, if_name);
	if(sock > 0)
		ret = wf_sendto_ip(sock, data, len, 0, ip, port);
	printf("sending magic packet to %s:%d with %s %s%s \n", ip, port, pmac, ret<0 ? "[failed: " : "", ret<0 ? wf_socket_error(NULL) : "" );

	return 0;
}

static void time_usage()
{
	fprintf(stderr, "wftool time usage: \n"
		"wftool time [-t time-num] [--now] \n"
		);
}

int cmd_time(int argc, char **argv)
{
	int i=1, ret=0;
	int set_now = 0;
	int tm = 0;
	time_t  time_now;
	struct tm *local_time;

	while(argv[++i])
	{
		if( strcmp(argv[i], "-t") == 0 && argv[++i]){
			tm = atoi(argv[i]);
			if(tm <= 0){
				printf("invalid tm: %s \n", argv[i]);
				return -1;
			}
		}
		else if( strcmp(argv[i], "--now") == 0 ){
			set_now = 1;
		}
		else{
			time_usage();
			return 0;
		}
	}

	if(tm > 0){
		time_now = (time_t)tm;
		local_time = localtime(&time_now);
		printf("--- -t ---\n");
		printf("time: %d \n", tm);
		printf("localtime: %04d.%02d.%02d-%02d:%02d:%02d \n", 
			local_time->tm_year+1900, local_time->tm_mon+1, local_time->tm_mday,
			local_time->tm_hour, local_time->tm_min, local_time->tm_sec);
	}

	if(set_now){
		time(&time_now);
		local_time = localtime(&time_now);
		printf("--- now ---\n");
		printf("time: %ld \n", time_now);
		printf("localtime: %04d.%02d.%02d-%02d:%02d:%02d  week: %d \n", 
			local_time->tm_year+1900, local_time->tm_mon+1, local_time->tm_mday,
			local_time->tm_hour, local_time->tm_min, local_time->tm_sec, local_time->tm_wday);
	}

	return 0;
}


static void json_usage()
{
	fprintf(stderr, "wftool json usage: \n"
		"wftool json [-f format] [json-file] \n"
		);
}

int cmd_json(int argc, char **argv)
{
	int i=1, ret=0;
	cJSON *obj = NULL;
	char *str = NULL;
	int fmt = 0;
	
	if(argv[++i]){
		if(strcmp(argv[i], "-f") == 0)
			fmt = 1;
	}
	
	if(!fmt)
		--i;

	if(argv[++i]){
		obj = json_load_file(argv[i]);
	}
	else{
		json_usage();
		return 0;
	}

	if(obj){
		printf("json parse OK \n\n");
		if(fmt)
			str = cJSON_Print(obj);
		else
			str = cJSON_PrintUnformatted(obj);
		if(str){
			printf("%s \n", str);
			free(str);
		}
		cJSON_Delete(obj);
	}
	else{
		printf("json parse failed \n");
	}

	return 0;
}

static void exeindir_usage()
{
	fprintf(stderr, "wftool exeindir usage: \n"
		"wftool exeindir [--all] [--depth number] [-q quiet] [--cmd \"cmd string\"] \n"
		);
}

static char *cmd_exeindir_cmd = NULL;
static int cmd_exeindir_depth = 256;
static int cmd_exeindir_quiet = 0;

static int __exeindir(char *dir, char *parent_dir, int depth)
{
	DIR *d = NULL;
	struct dirent *file = NULL;
	struct stat sb;
	char cur_dir[256] = {0};

	if(dir){
		if(!depth)
			return 0;
		chdir(dir);
		--depth;
		getcwd(cur_dir, sizeof(cur_dir));
		if(!cmd_exeindir_quiet)
			wfprintf(">>>> in %s \n", cur_dir);
	}	
	else{
		getcwd(cur_dir, sizeof(cur_dir));
		dir = &cur_dir[0];
	}

	d = opendir(cur_dir);
	if(!d){
		wfprintf("error opendir: %s \n", cur_dir);
		return -1;
	}

	while((file = readdir(d)) != NULL){
		if(strncmp(file->d_name, ".", 1) == 0)
			continue;

		if( stat(file->d_name, &sb) >= 0 && S_ISDIR(sb.st_mode) ){
			__exeindir(file->d_name, cur_dir, depth);
		}
	}
	closedir(d);

	if(!cmd_exeindir_quiet)
		printf("\n");
	system(cmd_exeindir_cmd);
	if(!cmd_exeindir_quiet)
		printf("\n");
	
	if(parent_dir){
		if(!cmd_exeindir_quiet)
			wfprintf(">>>> out %s \n", cur_dir);
		chdir(parent_dir);
	}

	return 0;
}

int cmd_exeindir(int argc, char **argv)
{
	int i=1, ret=0;
	int all = 0;
	char **exe_dir = NULL;
	int dir_num = 0;
	char cur_dir[256] = {0};
	struct stat sb;

	exe_dir = (char **)malloc(sizeof(char *) * argc);
	while(argv[++i])
	{
		if( strcmp(argv[i], "--cmd") == 0 && argv[++i]){
			cmd_exeindir_cmd = argv[i];
		}
		else if( strcmp(argv[i], "--depth") == 0 && argv[++i]){
			cmd_exeindir_depth = atoi(argv[i]);
			if(cmd_exeindir_depth < 0)
				cmd_exeindir_depth = 0;
		}
		else if( strcmp(argv[i], "--all") == 0 ){
			all= 1;
		}
		else if( strcmp(argv[i], "-q") == 0 ){
			cmd_exeindir_quiet = 1;
		}
		else{
			if(!exe_dir){
				wfprintf("malloc error \n");
				return 0;
			}
			//if(strncmp(argv[i], ".", 1))		// not need
				exe_dir[dir_num++] = argv[i];
			//WFT_DEBUG("%p  %s    %p  %s \n", argv[i], argv[i], exe_dir[dir_num-1], exe_dir[dir_num-1]);
		}
	}
	if(!cmd_exeindir_cmd){
		wfprintf("no command need to execrate \n");
		return 0;
	}

	//WFT_DEBUG("all=%d  dir_num=%d \n", all, dir_num);
	if(all){
		__exeindir(NULL, NULL, cmd_exeindir_depth);
	}
	else if(dir_num > 0){
		if(cmd_exeindir_depth < 1)
			cmd_exeindir_depth = 1;
		getcwd(cur_dir, sizeof(cur_dir));
		for(i=0; i<dir_num; i++){
			//WFT_DEBUG("%p  exe_dir: %s \n", exe_dir[i], exe_dir[i]);
			if( stat(exe_dir[i], &sb) >= 0 && S_ISDIR(sb.st_mode) ){
				__exeindir(exe_dir[i], cur_dir, cmd_exeindir_depth);
			}
			else
				wfprintf("%s is not directory \n", exe_dir[i]);
		}	
	}
	else
		system(cmd_exeindir_cmd);

	if(exe_dir)
		free(exe_dir);

	return 0;
}

struct cmd_t
{
	char cmd[16];
	int (*init_call)(int argc, char **argv);
	void (*usage_call)(void);
	int (*cmd_call)(int argc, char **argv);
};

struct cmd_t cmd_list[] = {
	{"ntorn", NULL, txt_usage, cmd_ntorn},
	{"rnton", NULL, txt_usage, cmd_rnton},
	{"a1torn", NULL, txt_usage, cmd_a1torn},
	{"udp", NULL, udp_usage, cmd_udp},
	{"tcp", NULL, tcp_usage, cmd_tcp},
	{"gethost", NULL, gethost_usage, cmd_gethost},
	{"asc", NULL, asc_usage, cmd_asc},
	{"wol", NULL, wol_usage, cmd_wol},
	{"time", NULL, time_usage, cmd_time},
	{"json", NULL, json_usage, cmd_json},
	{"exeindir", NULL, exeindir_usage, cmd_exeindir},
};

void wftool_usage()
{
	int idx = 0;
	
	fprintf(stderr, "wftool usage: \n"
		"\twftool [cmd] [option] [...] \n"
		"cmd list: \n"
		"  help \n"
		);

	for(idx=0; idx<ARRAY_NUM(cmd_list); idx++){
		fprintf(stderr, "  %s \n", cmd_list[idx].cmd);
	}
	
	fprintf(stderr, "note:\"wftool help <cmd>\" for help on a specific cmd \n");
}

void print_usage(char *cmd)
{
	struct cmd_t *pcmd = NULL;
	int idx = 0;
	
	if(cmd == NULL)
		wftool_usage();
	else{
		for(idx=0; idx<ARRAY_NUM(cmd_list); idx++){
			if(strcmp(cmd, cmd_list[idx].cmd) == 0){
				pcmd = &cmd_list[idx];
			}
		}
	}
	if(pcmd){
		if(pcmd->usage_call)
			pcmd->usage_call();
		else
			wfprintf("no usage \n");
	}
	else
		wftool_usage();

	exit(0);
}

int main(int argc, char **argv)
{
	int ret=0;
	struct cmd_t *pcmd = NULL;
	int idx = 0;

	printf("sid: %d  pgid: %d  pid: %d  ppid: %d \n", getsid(0), getpgid(0), getpid(), getppid());	
	if(argc >= 2)
	{
		if( strcmp(argv[1], "-h") == 0 )
			wftool_usage();
		else if( strcmp(argv[1], "help") == 0 )
			print_usage(argv[2]);
		else{
			for(idx=0; idx<ARRAY_NUM(cmd_list); idx++){
				if(strcmp(argv[1], cmd_list[idx].cmd) == 0){
					pcmd = &cmd_list[idx];
				}
			}
		}

		if(pcmd){
			if(pcmd->init_call){
				ret = pcmd->init_call(argc, argv);
				if(ret < 0){
					wfprintf("error: command init failed: %s \n", pcmd->cmd);
					return 1;
				}
			}
			if(pcmd->cmd_call){
				strcpy(print_name, pcmd->cmd);
				pcmd->cmd_call(argc, argv);
			}
			else
				wfprintf("error: can't execute %s \n", pcmd->cmd);
		}
		else
			wftool_usage();
	}
	else{
		wftool_usage();
	}

	return ret;
}

