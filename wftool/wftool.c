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

#include <net/if.h> // struct ifreq
#include <linux/if_tun.h> // TUNSETIFF

#include "libwf.h"

#include "wftool.h"

char print_name[32] = "wftool";
int wft_debug = 0;

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

char *get_argv(int argc, char **argv, int *idx, char *key, int have_value)
{
	int i = *idx;
	char *ret = NULL;
	if(!argv[i] || strcmp(argv[i], key) != 0)
		return NULL;
	if(!have_value || (have_value && argv[++i]))
		ret = argv[i];
	*idx = i;
	return ret;
}
char *get_argv_next(int argc, char **argv, int *idx, char *key, int have_value)
{
	char *ret = get_argv(argc, argv, idx, key, have_value);
	*idx = *idx + 1;
	return ret;
}

char *wf_argv[1024] = {0};
int wf_argc = 0;

static char asc_buf[10240] = {'\0'};
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
	int i=0;
	
	while(argv[++i])
	{
		if( strcmp(argv[i], "-s") == 0 && argv[++i])
			txt->sfile = strdup(argv[i]);
		else if( strcmp(argv[i], "-d") == 0 && argv[++i])
			txt->dfile = strdup(argv[i]);
		else if( strcmp(argv[i], "--debug") == 0)
			wft_debug = 1;
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

// ************************************   udp
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
	int i=0, ret=0;
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
// ************************************   udp     *********** end

// ************************************   tcp
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
	int i=0, ret=0;
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
// ************************************   tcp     *********** end

// ************************************   gethost
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
	int i = 0;
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
		if(argv[1])
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
// ************************************   gethost     *********** end

// ************************************   asc
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
	int i=0, j=0;
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
// ************************************   asc     *********** end

// ************************************   wol
void wol_usage()
{
	fprintf(stderr, "wftool wol usage: \n"
		"wftool wol [-i ip-address] [-p port] [-o interface-dev-name] [--passwd xx-xx-xx-xx-xx-xx] mac \n"
		);
}

int cmd_wol(int argc, char **argv)
{
	int i=0, ret=0;
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
// ************************************   wol     *********** end

// ************************************   time
static void time_usage()
{
	fprintf(stderr, "wftool time usage: \n"
		"wftool time [-t time-num] [--now] \n"
		);
}

int cmd_time(int argc, char **argv)
{
	int i=0, ret=0;
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
// ************************************   time     *********** end

// ************************************   json
static void json_usage()
{
	fprintf(stderr, "wftool json usage: \n"
		"wftool json [-f format] [json-file] \n"
		);
}

int cmd_json(int argc, char **argv)
{
	int i=0, ret=0;
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
// ************************************   json     *********** end

// ************************************   exeindir
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
	int i=0, ret=0;
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
// ************************************   exeindir     *********** end

// ************************************   text
static void text_usage()
{
	fprintf(stderr, "wftool text usage: \n"
		"wftool text [cmd] [option] file \n"
		"    cmd: rmdup \n"
		);
}

struct text_line_t
{
	char *line;
	char *line_end;
	unsigned int line_len;
};

struct text_line_list
{
	int line_num;
	struct text_line_t *line_array;
};

enum TEXT_CMD{
	TEXT_CAT,
	TEXT_RMDUP,
};
enum TEXT_CMD text_cmd = TEXT_CAT;
char *text_global_buff = NULL;

int get_text_line_num()
{
	int i = 0, num = 1;

	if(text_global_buff[0] == '\0')
		return 0;
	while(text_global_buff[i] != '\0'){
		if(text_global_buff[i] == '\n')
			++num;
		++i;
	}
	return num;
}

void print_text_line_list(struct text_line_list *line_list)
{
	int i = 0;

	for(i=0; i<line_list->line_num; i++){
		if(!line_list->line_array[i].line)
			continue;
		printf("%s\n", line_list->line_array[i].line);
	}
}

struct text_line_list *get_text_line_list(struct text_line_list *line_list)
{
	struct text_line_list *lines = line_list, *malloc_lines = NULL;
	int i = 0, num = 0, len = 0;

	if(!lines){
		malloc_lines = (struct text_line_list *)malloc(sizeof(struct text_line_list));
		lines = malloc_lines;
	}
	if(!lines){
		printf("error: %s \n", wf_std_error(NULL));
		return NULL;
	}
	memset(lines, 0, sizeof(struct text_line_list));

	lines->line_num = get_text_line_num();
	lines->line_array = (struct text_line_t *)malloc(sizeof(struct text_line_t) * lines->line_num);
	if(!lines->line_array){
		printf("error: %s \n", wf_std_error(NULL));
		if(malloc_lines)
			free(malloc_lines);
		return NULL;
	}
	memset(lines->line_array, 0, sizeof(struct text_line_t) * lines->line_num);

	lines->line_array[num].line = &text_global_buff[i];
	while(text_global_buff[i] != '\0'){
		++len;
		if(text_global_buff[i] == '\n'){
			lines->line_array[num].line_end = &text_global_buff[i];
			lines->line_array[num].line_len = len;
			text_global_buff[i] = '\0';
			//printf("[%d] %s\n", num, lines->line_array[num].line);
			len = 0;
			++num;
			lines->line_array[num].line = &text_global_buff[i+1];
		}
		++i;
	}
	if(lines->line_array[num].line)
		lines->line_array[num].line_end = &text_global_buff[i-1];

	return lines;
}

int cmd_text_rmdup(char *path)
{
	struct stat st;
	FILE *fp = NULL;
	size_t r_read;
	int i = 0, j = 0, is_cmp = 0;
	struct text_line_list tl_list;
	
	if(stat(path, &st) < 0){
		printf("error: %s \n", wf_std_error(NULL));
		return -1;
	}

	if(!st.st_size)
		return 0;
	text_global_buff = (char *)malloc(st.st_size + 1);
	if(!text_global_buff){
		printf("error: %s \n", wf_std_error(NULL));
		return -1;
	}
	memset(text_global_buff, 0, st.st_size + 1);

	fp = fopen(path,"r");
	if(fp == NULL){
		printf("error: %s \n", wf_std_error(NULL));
		goto ERR_END;
	}

	r_read = fread(text_global_buff, 1, st.st_size, fp);
	if( r_read <= 0 ){
		printf("error: %s \n", wf_std_error(NULL));
		goto ERR_END;
	}
	text_global_buff[r_read] = '\0';
	fclose(fp);
	fp = NULL;

	if(!get_text_line_list(&tl_list))
		goto ERR_END;

	if(text_cmd == TEXT_CAT)
		goto CAT;
	for(i=0; i<tl_list.line_num; i++){
		if(!tl_list.line_array[i].line)
			continue;
		for(j=0; j<tl_list.line_num; j++){
			if(i == j || !tl_list.line_array[j].line)
				continue;
			if(strcmp(tl_list.line_array[i].line, tl_list.line_array[j].line) == 0){
				tl_list.line_array[j].line = NULL;
			}
		}
	}
CAT:
	print_text_line_list(&tl_list);

ERR_END:
	if(text_global_buff)
		free(text_global_buff);
	if(fp)
		fclose(fp);
	if(tl_list.line_array)
		free(tl_list.line_array);
	return -1;
}

struct arg_parse_t cmd_text_arg_list[]={
		{"rmdup", &text_cmd, 1, 0, NULL, ARG_VALUE_TYPE_INT, TEXT_RMDUP, NULL},
		{NULL, NULL, 0, 0, NULL, 0, 0, NULL},
};
int cmd_text(int argc, char **argv)
{
	int i = 0, ret = 0;
	char *file = NULL;
	
	ret = arg_parse(argc, argv, cmd_text_arg_list, &wf_argc, wf_argv);
	if(ret < 0){
		printf("parse arg failed \n");
		return ret;
	}
	if(wf_argc >= 2)
		file = wf_argv[wf_argc-1];
	else{
		printf("no file \n");
		return -1;
	}

	if(text_cmd == TEXT_RMDUP || text_cmd == TEXT_CAT)
		cmd_text_rmdup(file);

	return 0;
}
// ************************************   text     *********** end

// ************************************   qqrobot
#define CMD_QQROBOT_DEBUG		0

#define WGET_PATH	"/usr/bin/wget"
#define WGETHTTP_COOKIE_MAXNUM		20

static char *wgethttp_find_cookie(char *buf, char **cookie_end)
{
	char *h_cookie = strstr(buf, "Set-Cookie");
	char *s_cookie = NULL, *e_cookie = NULL;
	
	if(!h_cookie)
		return NULL;
	s_cookie = h_cookie + strlen("Set-Cookie: ");
	if(*s_cookie == '\0')
		return NULL;
	e_cookie = strchr(s_cookie, ';');
	if(!e_cookie)
		return NULL;
	*cookie_end = e_cookie;
	return s_cookie;
}

static char *wgethttp_find_cookie_next(char **buf)
{
	char *s_cookie = NULL, *cookie_end = NULL;
	
	s_cookie = wgethttp_find_cookie(*buf, &cookie_end);
	if(s_cookie){
		*cookie_end = '\0';
		*buf = cookie_end + 1;
	}
	return s_cookie;
}

static FILE *mkstemp_fp(char *path, char *mode)
{
	int fd = 0;
	FILE *fp = NULL;

	fd = mkstemp(path);
	if(fd > 0){
		fp = fdopen(fd, mode);
		if(!fp)
			close(fd);
	}
	return fp;
}



#define SMARTQQ_LOGIN_COOKIE_PATH	"./smartqq_login_cookie"
#define SMARTQQ_PTQRSHOW_COOKIE_PATH	"./smartqq_ptqrshow_cookie"
#define SMARTQQ_PTQRLOGIN_PATH	"./smartqq_ptqrlogin"

static unsigned int smartqq_get_ptqrtoken()
{
	FILE *fp = fopen(SMARTQQ_PTQRSHOW_COOKIE_PATH, "r");
	char buf[1024] = {0}, *qrsig = NULL;
	int len = 0, i = 0, e = 0;
	unsigned int token = 0;

	if(!fp)
		return 0;

	while(fgets(buf, sizeof(buf), fp)){
		qrsig = strstr(buf, "qrsig");
		if(qrsig)
			break;
	}
	fclose(fp);
	if(!qrsig)
		return 0;

	qrsig += 5;
	while(*qrsig == ' ' || *qrsig == '\t')
		++qrsig;
	len = strlen(qrsig);
	if(len <= 0)
		return 0;
	printf("qrsig=[");
	for(i=0; i<len; i++){
		if(qrsig[i] == '\n' || qrsig[i] == '\t' || qrsig[i] == ' ')
			break;
		e += (e<<5) + (int)qrsig[i];
		printf("%c", qrsig[i]);
	}
	printf("]\n");
	if(!e)
		return 0;
	token = 0x7FFFFFFF & e;
	return token;
}

static int smartqq_login()
{
	int ret = -1, i=-1, len = 0;
	char *argv[15], *cookie[WGETHTTP_COOKIE_MAXNUM], *cookie_buf = &asc_buf[0];
	char tmp_buf[1024] = {0}, ptqrtoken_str[32] = {0};
	int cookie_num = 0;
	unsigned int ptqrtoken = 0;
	pid_t pid;
//------------------- https://ui.ptlogin2.qq.com/cgi-bin/login
	argv[++i] = "wget";
	argv[++i] = "--save-cookies="SMARTQQ_LOGIN_COOKIE_PATH;
	argv[++i] = "--keep-session-cookies";
#if CMD_QQROBOT_DEBUG
	argv[++i] = "-d";
#endif
	argv[++i] = "-O";
	argv[++i] = "/dev/null";
	argv[++i] = "https://ui.ptlogin2.qq.com/cgi-bin/login?daid=164&target=self&style=16&mibao_css=m_webqq&appid=501004106"
		"&enable_qlogin=0&no_verifyimg=1&s_url=http%3A%2F%2Fw.qq.com%2Fproxy.html&f_url=loginerroralert&strong_login=1"
		"&login_state=10&t=20131024001";
	argv[++i] = NULL;
#if CMD_QQROBOT_DEBUG
	pid = create_child_process(WGET_PATH, argv, 0, pipe_fd);
#else
	pid = create_child_process(WGET_PATH, argv, 1, NULL);
#endif
	if(pid < 0){
		wfprintf("create_child_process failed: %s \n", wf_std_error(NULL));
		return -1;
	}
	waitpid_sec(pid, NULL, 0);

#if CMD_QQROBOT_DEBUG
	len = read(pipe_fd[0], asc_buf, sizeof(asc_buf));
	if(len <=0 ){
		wfprintf("read: %s \n", wf_std_error(NULL));
		return -1;
	}
	printf("%s\n", asc_buf);
#endif
//------------------- https://ssl.ptlogin2.qq.com/ptqrshow
	i = -1;
	argv[++i] = "wget";
	argv[++i] = "--load-cookies="SMARTQQ_LOGIN_COOKIE_PATH;
	argv[++i] = "--save-cookies="SMARTQQ_PTQRSHOW_COOKIE_PATH;
	argv[++i] = "--keep-session-cookies";
	//argv[++i] = "-d";
	argv[++i] = "-O";
	argv[++i] = "/dev/null";
	argv[++i] = "https://ssl.ptlogin2.qq.com/ptqrshow?appid=501004106&e=0&l=M&s=5&d=72&v=4&t=0.9142399367333609";
	argv[++i] = NULL;
#if CMD_QQROBOT_DEBUG
	pid = create_child_process(WGET_PATH, argv, 0, pipe_fd);
#else
	pid = create_child_process(WGET_PATH, argv, 1, NULL);
#endif
	if(pid < 0){
		wfprintf("create_child_process failed: %s \n", wf_std_error(NULL));
		return -1;
	}
	waitpid_sec(pid, NULL, 0);

#if CMD_QQROBOT_DEBUG
	len = read(pipe_fd[0], asc_buf, sizeof(asc_buf));
	if(len <=0 ){
		wfprintf("read: %s \n", wf_std_error(NULL));
		return -1;
	}
	printf("%s\n", asc_buf);
#endif
//-------------------- https://ssl.ptlogin2.qq.com/ptqrlogin
	ptqrtoken = smartqq_get_ptqrtoken();
	if(!ptqrtoken){
		printf("smartqq_get_ptqrtoken failed \n");
		return -1;
	}
	sprintf(ptqrtoken_str, "%d", ptqrtoken);
	strcpy(tmp_buf, "https://ssl.ptlogin2.qq.com/ptqrlogin?ptqrtoken=");
	strcat(tmp_buf, ptqrtoken_str);
	strcat(tmp_buf, "&webqq_type=10&remember_uin=1&login2qq=1&aid=501004106"
		"&u1=http%3A%2F%2Fw.qq.com%2Fproxy.html%3Flogin2qq%3D1%26webqq_type%3D10&ptredirect=0&ptlang=2052&daid=164"
		"&from_ui=1&pttype=1&dumy=&fp=loginerroralert&action=0-0-32750&mibao_css=m_webqq&t=undefined&g=1&js_type=0&js_ver=10197"
		"&login_sig=&pt_randsalt=0");
	i = -1;
	argv[++i] = "wget";
	//argv[++i] = "-d";
	argv[++i] = "-O";
	argv[++i] = SMARTQQ_PTQRLOGIN_PATH;
	argv[++i] = &tmp_buf[0];
	argv[++i] = NULL;
	while(1){
#if CMD_QQROBOT_DEBUG
		pid = create_child_process(WGET_PATH, argv, 0, pipe_fd);
#else
		pid = create_child_process(WGET_PATH, argv, 1, NULL);
#endif
		if(pid < 0){
			wfprintf("create_child_process failed: %s \n", wf_std_error(NULL));
			return -1;
		}
		waitpid_sec(pid, NULL, 0);
#if CMD_QQROBOT_DEBUG
		len = read(pipe_fd[0], asc_buf, sizeof(asc_buf));
		if(len <=0 ){
			wfprintf("read: %s \n", wf_std_error(NULL));
			return -1;
		}
		printf("%s\n", asc_buf);
#endif
		break;
	}
	
	return 0;
}

static int cmd_qqrobot(int argc, char **argv)
{
#if CMD_QQROBOT_DEBUG
	if(init_pipe() < 0){
		wfprintf("init_pipe: %s \n", wf_std_error(NULL));
		return -1;
	}
	//printf("pipe_fd:  %d  %d \n", pipe_fd[0], pipe_fd[1]);
#endif

	smartqq_login();

#if CMD_QQROBOT_DEBUG
	close_pipe();
#endif
	return 0;
}
// ************************************   qqrobot     *********** end


// ************************************   usleep
void usleep_usage()
{
	fprintf(stderr, "wftool usleep usage: \n"
		"wftool usleep us \n"
		);
}

int cmd_usleep(int argc, char **argv)
{
	unsigned int us = 0;

	if(!argv[1]){
		usleep_usage();
		return 0;
	}
	
	us = atoi(argv[1]);
	
	return usleep(us);
}

// ************************************   usleep     *********** end


// ************************************   nl
void nl_usage()
{
	fprintf(stderr, "wftool nl usage: \n"
		"wftool nl [cmd] [option] \n"
		"    cmd: send listen send-listen \n"
		"    --set-protocol \n"
		"    --set-groups \n"
		"    --set-type \n"
		"    --set-flags \n"
		"    --dpid \n"
		"    --dgroups \n"
		"    --msg: send data \n"
		"    --pkt: send packets. when cmd is listen: listen packets \n"
		"    --resp-pkt: listen packets \n"
		"    --asc \n"
		);
}

enum CMD_NL_ACTION{
	NL_ACT_SEND,
	NL_ACT_LISTEN,
	NL_ACT_SEND_LISTEN,
};

struct cmd_nl_info{
	enum CMD_NL_ACTION action;
	int protocol;
	unsigned int groups;
	unsigned int type;
	unsigned int flags;
	unsigned int dpid;
	unsigned int dgroups;
	char *msg;
	int pkt;
	int resp_pkt;
	int print_asc;

	int msg_len;
	nlHandler hdl;
	unsigned char *buffer;
	unsigned int buffer_size;
	unsigned int pkt_cnt;
	unsigned long bytes_cnt;
};
static struct cmd_nl_info nl_info;
static struct arg_parse_t cmd_nl_arg_list[]={
		{"--set-protocol", &nl_info.protocol, 0, 1, NULL, ARG_VALUE_TYPE_INT, NL_ACT_SEND, NULL},
		{"--set-groups", &nl_info.groups, 0, 1, NULL, ARG_VALUE_TYPE_UINT, 0, NULL},
		{"--set-type", &nl_info.type, 0, 1, NULL, ARG_VALUE_TYPE_UINT, 0, NULL},
		{"--set-flags", &nl_info.flags, 0, 1, NULL, ARG_VALUE_TYPE_UINT, 0, NULL},
		{"--dpid", &nl_info.dpid, 0, 1, NULL, ARG_VALUE_TYPE_UINT, 0, NULL},
		{"--dgroups", &nl_info.dgroups, 0, 1, NULL, ARG_VALUE_TYPE_UINT, 0, NULL},
		{"--msg", &nl_info.msg, 0, 1, arg_deal_default, 0, 0, NULL},
		{"--pkt", &nl_info.pkt, 0, 1, NULL, ARG_VALUE_TYPE_INT, 1, NULL},
		{"--resp-pkt", &nl_info.resp_pkt, 0, 1, NULL, ARG_VALUE_TYPE_INT, 1, NULL},
		{"--asc", &nl_info.print_asc, 0, 0, NULL, ARG_VALUE_TYPE_INT, 1, NULL},
		arg_parse_t_init_null
};

static void nl_exit_call(int sig)
{
	if(nl_info.hdl.sockfd > 0)
		close(nl_info.hdl.sockfd);
	if(nl_info.action == NL_ACT_LISTEN || nl_info.action == NL_ACT_SEND_LISTEN){
		printf("\nrecv finish: %lu bytes  %d packets  from %u addrs \n", 
			nl_info.bytes_cnt, nl_info.pkt_cnt, wf_get_kv_count());
		wf_kv_table_destory();
	}
	printf("exit...\n");
	exit(0);
}

static int cmd_nl(int argc, char **argv)
{
	int i = 1, ret = 0;
	struct sockaddr_nl from_addr;
	
	if( strcmp(argv[1], "send") == 0 )
		nl_info.action = NL_ACT_SEND;
	else if( strcmp(argv[1], "listen") == 0 )
		nl_info.action = NL_ACT_LISTEN;
	else if( strcmp(argv[1], "send-listen") == 0 )
		nl_info.action = NL_ACT_SEND_LISTEN;
	else{
		i = 0;
		nl_info.action = NL_ACT_SEND;
	}
	nl_info.pkt = 1;
	nl_info.resp_pkt = 1;

	if(arg_parse(argc-i, argv+i, cmd_nl_arg_list, NULL, NULL) < 0){
		nl_usage();
		return 0;
	}

	if(nl_info.action == NL_ACT_LISTEN && nl_info.pkt > nl_info.resp_pkt)
		nl_info.resp_pkt = nl_info.pkt;
	if(nl_info.msg)
		nl_info.msg_len = strlen(nl_info.msg) + 1;

	if(nl_socket(&nl_info.hdl, nl_info.protocol, nl_info.groups) == NULL){
		printf("error: %s \n", wf_socket_error(NULL));
		return 0;
	}

	nl_info.buffer = (unsigned char *)&asc_buf[0];
	nl_info.buffer_size = 8192;
	if(nlmsg_init(&nl_info.hdl, (unsigned short)nl_info.type, (unsigned short)nl_info.flags, nl_info.buffer, nl_info.buffer_size) < 0){
		printf("error: %s \n", wf_socket_error(NULL));
		return 0;
	}
	
	wf_registe_exit_signal(nl_exit_call);

	if(nl_info.action == NL_ACT_SEND || nl_info.action == NL_ACT_SEND_LISTEN){
		while(nl_info.pkt--){
			ret = nlmsg_send_data(&nl_info.hdl, nl_info.buffer, nl_info.dpid, nl_info.dgroups, nl_info.msg, nl_info.msg_len);
			if(ret > 0)
				printf("send OK: %d bytes \n", ret);
			else
				printf("error: %s \n", wf_socket_error(NULL));
		}

		if(nl_info.action == NL_ACT_SEND){
			close(nl_info.hdl.sockfd);
			return 0;
		}
	}

	while(nl_info.resp_pkt){
		memset(&from_addr, 0, sizeof(from_addr));
		memset(nl_info.buffer, 0, nl_info.buffer_size);
		if(nl_info.action == NL_ACT_SEND_LISTEN)
			ret = nlmsg_recv(&nl_info.hdl, nl_info.buffer, nl_info.buffer_size, &from_addr);
		else
			ret = nlmsg_recv_no_seq(&nl_info.hdl, nl_info.buffer, nl_info.buffer_size, &from_addr);
		if(ret > 0){
			--nl_info.resp_pkt;
			++nl_info.pkt_cnt;
			nl_info.bytes_cnt += ret;
			wf_put_kv(&from_addr, sizeof(from_addr), &from_addr, sizeof(from_addr));
			printf("recv OK: %d bytes from pid=%d groups=%d  [pkt id: %d]\n", ret, from_addr.nl_pid, from_addr.nl_groups, nl_info.pkt_cnt);
			if(nl_info.print_asc)
				print_strn((char *)nl_info.buffer, (unsigned int)ret);
			else
				print_bytes(nl_info.buffer, (unsigned int)ret);
		}
		else{
			printf("ret=%d error: %s \n", ret, wf_socket_error(NULL));
		}
	}

	nl_exit_call(0);
	return 0;
}
// ************************************   nl     *********** end

// ************************************   base64
static void base64_usage()
{
	fprintf(stderr, "wftool base64 usage: \n"
		"wftool base64 [-e/--encode] [-d/--decode] <string/-f file> [-x/--hex] [-o/--out]\n"
		"    -x  --hex: output hexadecimal \n"
		"    -o  --out: output file \n"
		);
}

struct cmd_base64_info{
	int decode;
	char *str;
	char *file;
	int out_hex;
	char *out_file;
};

static struct cmd_base64_info base64_info;
static struct arg_parse_t cmd_base64_arg_list[]={
		{"-e", &base64_info.decode, 0, 0, NULL, ARG_VALUE_TYPE_INT, 0, NULL},
		{"--encode", &base64_info.decode, 0, 0, NULL, ARG_VALUE_TYPE_INT, 0, NULL},
		{"-d", &base64_info.decode, 0, 0, NULL, ARG_VALUE_TYPE_INT, 1, NULL},
		{"--decode", &base64_info.decode, 0, 0, NULL, ARG_VALUE_TYPE_INT, 1, NULL},
		{"-f", &base64_info.file, 0, 1, arg_deal_default, 0, 0, NULL},
		{"-x", &base64_info.out_hex, 0, 0, NULL, ARG_VALUE_TYPE_INT, 1, NULL},
		{"--hex", &base64_info.out_hex, 0, 0, NULL, ARG_VALUE_TYPE_INT, 1, NULL},
		{"-o", &base64_info.out_file, 0, 1, arg_deal_default, 0, 0, NULL},
		{"--out", &base64_info.out_file, 0, 1, arg_deal_default, 0, 0, NULL},
		arg_parse_t_init_null
};

static int cmd_base64(int argc, char **argv)
{
	int new_argc = 0, ret = 0, i = 0;
	char **new_argv = (char **)malloc(sizeof(char *) * argc);
	char *target = NULL;
	unsigned int str_len = 0, target_size = 0;
	struct base64_context bs_cxt;
	FILE *fp = NULL, *out_fp = NULL;
	char in[1024], out[1409];
	size_t read_len;

	if(!new_argv){
		wfprintf("malloc error \n");
		return 0;
	}
	if(arg_parse(argc, argv, cmd_base64_arg_list, &new_argc, new_argv) < 0){
		base64_usage();
		return 0;
	}
	if(new_argc > 1)
		base64_info.str = new_argv[new_argc-1];
	else if(!base64_info.file){
		base64_usage();
		return 0;
	}
	free(new_argv);

	if(base64_info.out_file){
		out_fp = fopen(base64_info.out_file, "w");
		if(!out_fp){
			wfprintf("fopen %s failed: %s \n", base64_info.out_file, strerror(errno));
			return 0;
		}
	}
	
	if(base64_info.str){
		str_len = (unsigned int)strlen(base64_info.str);
		if(base64_info.decode)
			target = (char *)base64_malloc_decode_target(str_len, &target_size);
		else
			target = (char *)base64_malloc_encode_target(str_len, &target_size);
		if(!target){
			wfprintf("malloc error \n");
			return 0;
		}

		if(base64_info.decode)
			ret = base64_decode(base64_info.str, str_len, (unsigned char *)target, target_size);
		else
			ret = base64_encode(base64_info.str, str_len, target, target_size);

		if(out_fp)
			fwrite(target, 1, ret, out_fp);
		printf("\n");
		if(base64_info.out_hex)
			print_bytes(target, ret);
		else
			print_strn(target, ret);
		
		free(target);
	}
	else{
		if(base64_info.decode)
			base64_decode_start(&bs_cxt);
		else
			base64_encode_start(&bs_cxt);
		fp = fopen(base64_info.file, "r");
		if(!fp){
			wfprintf("fopen %s failed: %s \n", base64_info.file, strerror(errno));
			return 0;
		}
		while(!feof(fp)){
			memset(in, 0, sizeof(in));
			memset(out, 0, sizeof(out));
			read_len = fread(in, 1, sizeof(in), fp);
			if(read_len > 0){
				if(base64_info.decode)
					ret = base64_decode_process(&bs_cxt, (char *)in, (unsigned int)read_len, (unsigned char *)&out[0], sizeof(out)-1);
				else
					ret = base64_encode_process(&bs_cxt, (unsigned char *)&in[0], (unsigned int)read_len, out, sizeof(out)-1);

				if(out_fp)
					fwrite(out, 1, ret, out_fp);
				printf("\n");
				if(base64_info.out_hex)
					print_bytes(out, ret);
				else
					print_strn(out, ret);
			}
		}
		memset(out, 0, sizeof(out));
		if(base64_info.decode)
			base64_decode_finish(&bs_cxt, (unsigned char *)&out[0], sizeof(out)-1);
		else
			base64_encode_finish(&bs_cxt, out, sizeof(out)-1);
		printf("%s\n", out);
		fclose(fp);
	}

	if(out_fp)
		fclose(out_fp);
	return 0;
}

// ************************************   base64     *********** end


// ************************************   tun / tap
static void tun_usage()
{
	fprintf(stderr, "wftool tun usage: \n"
		"wftool tun \n"
		);
}
static void tap_usage()
{
	fprintf(stderr, "wftool tun usage: \n"
		"wftool tap \n"
		);
}

/* Flags: IFF_TUN   - TUN device (no Ethernet headers)
 *        IFF_TAP   - TAP device
 *        IFF_NO_PI - Do not provide packet information
 */
int tun_tap_create(int flags, char *ifname)
{
	struct ifreq ifr;
    int fd, err;
    char *clonedev = "/dev/net/tun";

    if ((fd = open(clonedev, O_RDWR)) < 0) {
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = flags;

    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
        close(fd);
        return err;
    }
	strcpy(ifname, ifr.ifr_name);
    printf("Open tun/tap device: %s for reading...\n", ifr.ifr_name);

    return fd;
}

static int cmd_tun(int argc, char **argv)
{
	int fd = -1, nread = 0;
	char ifname[18] = {'\0'};
	char cmdline[256] = {'\0'};
	char buffer[2048] = {'\0'};

	if(!strcmp("tun", argv[0]))
		fd = tun_tap_create(IFF_TUN | IFF_NO_PI, ifname);
	else
		fd = tun_tap_create(IFF_TAP | IFF_NO_PI, ifname);
	wfprintf("fd=%d  ifname=%s \n", fd, ifname);
	sprintf(cmdline, "ip addr add 192.8.8.2/24 dev %s", ifname);
	system(cmdline);
	sprintf(cmdline, "ip link set %s up", ifname);
	system(cmdline);

	while(1){
		nread = read(fd, buffer, sizeof(buffer));
		wfprintf("nread=%d \n", nread);
		print_bytes((unsigned char *)&buffer[0], (unsigned int)nread);
	}
	close(fd);

	return 0;
}

static int cmd_tap(int argc, char **argv)
{
	return cmd_tun(argc, argv);
}


// ************************************   tun / tap     *********** end



int wftool_cmd_init_call(int argc, char **argv, struct child_cmd_t *pcmd)
{
	strcpy(print_name, pcmd->cmd);
	return 0;
}

// ************************************   tftp
extern void tftpc_usage();
extern int cmd_tftpc(int argc, char **argv);

// ************************************   tftp     *********** end

struct child_cmd_t cmd_list[] = {
	{"ntorn", wftool_cmd_init_call, txt_usage, cmd_ntorn},
	{"rnton", wftool_cmd_init_call, txt_usage, cmd_rnton},
	{"a1torn", wftool_cmd_init_call, txt_usage, cmd_a1torn},
	{"udp", wftool_cmd_init_call, udp_usage, cmd_udp},
	{"tcp", wftool_cmd_init_call, tcp_usage, cmd_tcp},
	{"gethost", wftool_cmd_init_call, gethost_usage, cmd_gethost},
	{"asc", wftool_cmd_init_call, asc_usage, cmd_asc},
	{"wol", wftool_cmd_init_call, wol_usage, cmd_wol},
	{"time", wftool_cmd_init_call, time_usage, cmd_time},
	{"json", wftool_cmd_init_call, json_usage, cmd_json},
	{"exeindir", wftool_cmd_init_call, exeindir_usage, cmd_exeindir},
	{"text", wftool_cmd_init_call, text_usage, cmd_text},
	{"qqrobot", wftool_cmd_init_call, NULL, cmd_qqrobot},
	{"tftpc", wftool_cmd_init_call, tftpc_usage, cmd_tftpc},
	{"usleep", wftool_cmd_init_call, usleep_usage, cmd_usleep},
	{"nl", wftool_cmd_init_call, nl_usage, cmd_nl},
	{"base64", wftool_cmd_init_call, base64_usage, cmd_base64},
	{"tun", wftool_cmd_init_call, tun_usage, cmd_tun},
	{"tap", wftool_cmd_init_call, tap_usage, cmd_tap},
};

int main(int argc, char **argv)
{
	return wf_child_cmd_mini(cmd_list, "wftool");
}

