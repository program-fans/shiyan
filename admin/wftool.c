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

enum ARG_VALUE_TYPE{
	ARG_VALUE_TYPE_NONE,
	ARG_VALUE_TYPE_CHAR,
	ARG_VALUE_TYPE_INT,
	ARG_VALUE_TYPE_LONG,
	ARG_VALUE_TYPE_LONGLONG,
	ARG_VALUE_TYPE_STRING,
};
struct arg_parse_t
{
	char *key;
	void *value;
	int arg_idx;
	int has_arg;
	int (*arg_deal)(char *arg_key, char *arg_value, void *value);
	enum ARG_VALUE_TYPE value_type;
	long long int set_number;
	char *set_string;
};

char *wf_argv[1024] = {0};
int wf_argc = 0;
int arg_parse_set_value(struct arg_parse_t *p_arg, char *data)
{
	int ret = 0;
	switch(p_arg->value_type){
	case ARG_VALUE_TYPE_CHAR:
		if(data)
			ret = sscanf(data, "%c", (char *)(p_arg->value));
		else
			*((char *)(p_arg->value)) = (char)(p_arg->set_number);
		break;
	case ARG_VALUE_TYPE_INT:
		if(data)
			ret = sscanf(data, "%d", (int *)(p_arg->value));
		else
			*((int *)(p_arg->value)) = (int)(p_arg->set_number);
		break;
	case ARG_VALUE_TYPE_LONG:
		if(data)
			ret = sscanf(data, "%ld", (long *)(p_arg->value));
		else
			*((long *)(p_arg->value)) = (long)(p_arg->set_number);
		break;
	case ARG_VALUE_TYPE_LONGLONG:
		if(data)
			ret = sscanf(data, "%lld", (long long int *)(p_arg->value));
		else
			*((long long int *)(p_arg->value)) = p_arg->set_number;
		break;
	case ARG_VALUE_TYPE_STRING:
		if(data)
			ret = sscanf(data, "%s", (char *)(p_arg->value));
 		else if(p_arg->set_string)
			strcpy((char *)(p_arg->value), p_arg->set_string);
		break;
	default:
		break;
	}

	if(data)
		return ret == 1 ? 0 : -1;
	else
		return 0;
}

int arg_parse(int argc, char **argv, struct arg_parse_t *arg_plist)
{
	int i = 0, ret = 0, is_match = 0;
	struct arg_parse_t *p_arg = NULL;

	wf_argv[0] = argv[0];
	wf_argc = 1;

	while(argv[++i]){
		is_match = 0;
		p_arg = arg_plist;
		while(p_arg && p_arg->key){
			if((p_arg->arg_idx > 0) && (i != p_arg->arg_idx)){
				++p_arg;
				continue;
			}
			if(strcmp(argv[i], p_arg->key) == 0){
				is_match = 1;
				if(p_arg->has_arg){
					if(argv[++i]){
						if(p_arg->arg_deal)
							ret = p_arg->arg_deal(argv[i-1], argv[i], p_arg->value);
						else if(p_arg->value_type > ARG_VALUE_TYPE_NONE && p_arg->value)
							ret = arg_parse_set_value(p_arg, argv[i]);
					}
				}
				else{
					if(p_arg->value_type > ARG_VALUE_TYPE_NONE && p_arg->value){
						arg_parse_set_value(p_arg, NULL);
					}
					else if(p_arg->arg_deal)
						ret = p_arg->arg_deal(argv[i], NULL, NULL);
				}
			}
			if(ret < 0)
				return ret;
			++p_arg;
		}
		if(!is_match)
			wf_argv[wf_argc++] = argv[i];
	}
	return 0;
}

int arg_deal_default(char *arg_key, char *arg_value, void *value)
{
	*((char **)value) = arg_value;
	return 0;
}

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
	
	ret = arg_parse(argc, argv, cmd_text_arg_list);
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

// ************************************   tftp
#define TFTP_BLOCKSIZE_DEFAULT 512 /* according to RFC 1350, don't change */
#define TFTP_TIMEOUT 5             /* seconds */

/* opcodes we support */

#define TFTP_RRQ   1
#define TFTP_WRQ   2
#define TFTP_DATA  3
#define TFTP_ACK   4
#define TFTP_ERROR 5
#define TFTP_OACK  6

struct tftp_t
{
	unsigned short opcode;
	union {
		struct wf_buffer rrq;
		struct wf_buffer wrq;
		struct {
			unsigned short block;
			char *download;
			int len;
		} data;
		struct {
			unsigned short block;
		} ack;
		struct {
			unsigned short errcode;
			char *errmsg;
		} err;
		struct wf_buffer oack;
	} u;
};

enum TFTP_CMD{
	TFTP_CMD_GET=1,
	TFTP_CMD_PUT,
	TFTP_CMD_MAX
};

struct tftp_arg_t
{
	int tftp_cmd;
	char *local_file;
	char *remote_file;
	int set_block_size;
	int set_hport;
	char *host;

	FILE *localfp;
	int server_first_port;
	struct sockaddr_in server_addr;
	unsigned short block_id;
	int want_option_ack;
	int finished;
};
struct tftp_arg_t tftp_arg;

void tftp_t_free(struct tftp_t *t, int free_self)
{
	if(!t)
		return;
	if(t->opcode == TFTP_RRQ)
		wf_buffer_free(&(t->u.rrq), 0);
	else if(t->opcode == TFTP_WRQ)
		wf_buffer_free(&(t->u.wrq), 0);
	else if(t->opcode == TFTP_OACK)
		wf_buffer_free(&(t->u.oack), 0);
	
	if(free_self)
		free(t);
	else
		memset(t, 0, sizeof(struct tftp_t));
}

static const char * const tftp_bb_error_msg[] = {
        "Undefined error",
        "File not found",
        "Access violation",
        "Disk full or allocation error",
        "Illegal TFTP operation",
        "Unknown transfer ID",
        "File already exists",
        "No such user"
};

static int tftp_blocksize_check(int blocksize, int bufsize)
{
        /* Check if the blocksize is valid:
         * RFC2348 says between 8 and 65464,
         * but our implementation makes it impossible
         * to use blocksizes smaller than 22 octets.
         */

        if ((bufsize && (blocksize > bufsize)) ||
            (blocksize < 8) || (blocksize > 65464)) {
                //bb_error_msg("bad blocksize");
                return 0;
        }

        return blocksize;
}

static char *tftp_option_get(char *buf, int len, char *option)
{
	int opt_val = 0;
	int opt_found = 0;
	int k;

	while (len > 0)
	{
		/* Make sure the options are terminated correctly */
		for (k = 0; k < len; k++) {
			if (buf[k] == '\0') {
			break;
			}
		}

		if (k >= len)
			break;

		if (opt_val == 0) {
			if (strcasecmp(buf, option) == 0)
				opt_found = 1;
		}
		else {
			if (opt_found)
				return buf;
		}
		
		k++;
		buf += k;
		len -= k;
		
		opt_val ^= 1;
	}

	return NULL;
}

static int tftp_recv(int socketfd, struct tftp_arg_t *arg, struct wf_buffer *packed_buffer, int timeout)
{
	struct timeval tv;
	fd_set rfds;
	struct sockaddr_in addr_from;
	
	if(timeout <= 0)
		timeout = TFTP_TIMEOUT;
	packed_buffer->len = 0;

	tv.tv_sec = TFTP_TIMEOUT;
	tv.tv_usec = 0;

	FD_ZERO(&rfds);
	FD_SET(socketfd, &rfds);

	switch (select(socketfd + 1, &rfds, NULL, NULL, &tv)) 
	{
	case 1:
		packed_buffer->len = wf_recvfrom(socketfd, (unsigned char *)(packed_buffer->data), 
			packed_buffer->size, 0, &addr_from);
		if(packed_buffer->len < 0){
			printf("recvfrom error: %s\n", wf_socket_error(NULL));
			return -packed_buffer->len;
		}

		if (tftp_arg.server_addr.sin_port == htons(tftp_arg.server_first_port)) {
			tftp_arg.server_addr.sin_port = addr_from.sin_port;
		}
		if (tftp_arg.server_addr.sin_port == addr_from.sin_port) {
			break;
		}
	case 0:
		printf("timeout \n");
		break;
	default:
		printf("select error: %s\n", wf_socket_error(NULL));
		return -1;
	}

	return packed_buffer->len;
}

static int tftp_unpack(struct tftp_arg_t *arg, struct wf_buffer *packed_buffer, struct tftp_t *tftp_data)
{
	int ret = 0;
	char *ptr = packed_buffer->data;
	unsigned short tmp_short = 0;
	struct wf_buffer *p_buf = NULL;

	tftp_t_free(tftp_data, 0);
	
	tftp_data->opcode = ntohs(*((unsigned short *) ptr));
	ptr += 2;
	tmp_short = ntohs(*((unsigned short *) ptr));

	switch(tftp_data->opcode)
	{
	case TFTP_DATA:
		tftp_data->u.data.block = tmp_short;
		ptr += 2;
		tftp_data->u.data.download = ptr;
		tftp_data->u.data.len = packed_buffer->len - 4;
		break;
	case TFTP_ACK:
		tftp_data->u.ack.block = tmp_short;
		break;
	case TFTP_ERROR:
		tftp_data->u.err.errcode = tmp_short;
		ptr += 2;
		tftp_data->u.err.errmsg = ptr;
		break;
	case TFTP_RRQ:
	case TFTP_WRQ:
	case TFTP_OACK:
		if(tftp_data->opcode == TFTP_RRQ)
			p_buf = &(tftp_data->u.rrq);
		else if(tftp_data->opcode == TFTP_WRQ)
			p_buf = &(tftp_data->u.wrq);
		else
			p_buf = &(tftp_data->u.oack);
		if(!wf_buffer_set(p_buf, ptr, packed_buffer->len - 2)){
			return -1;
		}
		break;
	default:
		printf("unknown opcode \n");
		return -1;
	}

	return ret;
}

static int tftp_pack(struct tftp_arg_t *arg, struct tftp_t *tftp_data, struct wf_buffer *packed_buffer)
{
	char *ptr = NULL, *packed_buffer_end = NULL;
	int too_long = 0, len = 0;
	int opcode = tftp_data->opcode;
	char *file_name = NULL;
	
	packed_buffer_end = &(packed_buffer->data[arg->set_block_size-1]);
	ptr = packed_buffer->data;

	if(!opcode){
		if(arg->tftp_cmd == TFTP_CMD_GET)
			opcode = TFTP_RRQ;
		else if(arg->tftp_cmd == TFTP_CMD_PUT)
			opcode = TFTP_WRQ;
	}
	*((unsigned short *) ptr) = htons(opcode);
	ptr += 2;

	if((arg->tftp_cmd == TFTP_CMD_GET && opcode == TFTP_RRQ) || 
		(arg->tftp_cmd == TFTP_CMD_PUT && opcode == TFTP_WRQ))
	{
		if(arg->tftp_cmd == TFTP_CMD_GET)
			file_name = arg->remote_file;
		else
			file_name = arg->local_file;
		len = strlen(file_name) + 1;

		if( (ptr + len) >= packed_buffer_end )
			too_long = 1;
		else{
			strcpy(ptr, file_name);
			ptr += len;
			*(ptr-1) = 0;
		}

		if(too_long || (packed_buffer_end -ptr) < 6){
			printf("too long filename \n");
			return -1;
		}

		memcpy(ptr, "octet", 6);
		ptr += 6;

		len = arg->set_block_size - 4; /* data block size */

		if (len != TFTP_BLOCKSIZE_DEFAULT) {
			if ((packed_buffer_end - ptr) < 15) {
				printf("too long filename \n");
				return -1;
			}

			/* add "blksize" + number of blocks  */
			memcpy(ptr, "blksize", 8);
			ptr += 8;

			len = snprintf(ptr, 6, "%d", len) + 1;
			ptr += len;

			arg->want_option_ack = 1;
		}
	}
	else if(arg->tftp_cmd == TFTP_CMD_GET && opcode == TFTP_ACK) {
		*((unsigned short *) ptr) = htons(arg->block_id);
		ptr += 2;
	}
	else if(arg->tftp_cmd == TFTP_CMD_PUT && opcode == TFTP_DATA) {
		*((unsigned short *) ptr) = htons(arg->block_id);
		ptr += 2;

		//len = read file;
		len = fread(ptr, 1, arg->set_block_size-4, arg->localfp);
		if(len < 0){
			printf("read error: %s\n", wf_std_error(NULL));
			return len;
		}

		if(len != (arg->set_block_size - 4))
			++arg->finished;
		ptr += len;
	}

	packed_buffer->len = ptr - packed_buffer->data;
	return 0;
}

void tftpc_usage()
{
	fprintf(stderr, "wftool tftpc usage: \n"
		"wftool tftpc [option] host[:port] \n"
		"    -g: get file from server \n"
		"    -p: put file to server \n"
		"    -l: local file \n"
		"    -r: remote file \n"
		"    -b: set block size \n"
		"    -P: set udp source port \n"
		);
}

struct arg_parse_t cmd_tftp_arg_list[]={
		{"-g", &(tftp_arg.tftp_cmd), 0, 0, NULL, ARG_VALUE_TYPE_INT, TFTP_CMD_GET, NULL},
		{"-p", &(tftp_arg.tftp_cmd), 0, 0, NULL, ARG_VALUE_TYPE_INT, TFTP_CMD_PUT, NULL},
		{"-l", &(tftp_arg.local_file), 0, 1, arg_deal_default, 0, 0, NULL},
		{"-r", &(tftp_arg.remote_file), 0, 1, arg_deal_default, 0, 0, NULL},
		{"-b", &(tftp_arg.set_block_size), 0, 1, NULL, ARG_VALUE_TYPE_INT, 0, NULL},
		{"-P", &(tftp_arg.set_hport), 0, 1, NULL, ARG_VALUE_TYPE_INT, 0, NULL},
		{NULL, NULL, 0, 0, NULL, 0, 0, NULL},
};

static int tftp_reset_send_buffer(struct tftp_arg_t *arg, int new_block_size, struct wf_buffer *send_buffer)
{
	if(new_block_size != arg->set_block_size){
		arg->set_block_size = new_block_size + 4;
		if(!wf_buffer_remalloc(send_buffer, arg->set_block_size)){
			return -1;
		}
	}
	return 0;
}

static int cmd_tftpc(int argc, char **argv)
{
	int ret = 0;
	int socketfd = -1;
	char *ch = NULL;
	int serverPort = 69;
	int new_set_block_size = TFTP_BLOCKSIZE_DEFAULT;
	
	struct tftp_t tftp_data, tftp_data_recv;
	struct wf_buffer send_buffer, recv_buffer;

	memset(&tftp_arg, 0, sizeof(tftp_arg));
	tftp_arg.set_block_size = TFTP_BLOCKSIZE_DEFAULT;
	tftp_arg.block_id = 1;
	
	ret = arg_parse(argc, argv, cmd_tftp_arg_list);
	if(ret < 0){
		printf("parse arg failed \n");
		return ret;
	}
	if(wf_argc >= 2)
		tftp_arg.host = wf_argv[wf_argc-1];

	if(tftp_arg.tftp_cmd < TFTP_CMD_GET || tftp_arg.tftp_cmd >= TFTP_CMD_MAX || !tftp_arg.host){
		tftpc_usage();
		return -1;
	}
	if((tftp_arg.tftp_cmd == TFTP_CMD_GET && !tftp_arg.remote_file) || 
		(tftp_arg.tftp_cmd == TFTP_CMD_PUT && !tftp_arg.local_file)){
		tftpc_usage();
		return -1;
	}
	if(tftp_arg.set_hport < 0 || tftp_arg.set_hport >= 65535){
		printf("srouce port is invalid [%d]\n", tftp_arg.set_hport);
		return -1;
	}
	if(!tftp_blocksize_check(tftp_arg.set_block_size, 0)){
		printf("bad blocksize [%d]\n", tftp_arg.set_block_size);
		return -1;
	}
	tftp_arg.set_block_size += 4;

	if(tftp_arg.tftp_cmd == TFTP_CMD_GET){
		if(tftp_arg.local_file)
			ch = tftp_arg.local_file;
		else
			ch = tftp_arg.remote_file;
		tftp_arg.localfp = fopen(ch, "w");
	}
	else{
		ch = tftp_arg.local_file;
		tftp_arg.localfp = fopen(ch, "r");
	}
	if(!tftp_arg.localfp){
		printf("fopen %s error: %s\n", ch, wf_std_error(NULL));
		return -1;
	}

	ch = strchr(tftp_arg.host, ':');
	if(ch){
		*ch = '\0';
		++ch;
		serverPort = atoi(ch);
		if(serverPort < 0 || serverPort >= 65535){
			printf("invalid host [%s]\n", tftp_arg.host);
			return -1;
		}
	}
	tftp_arg.server_first_port = serverPort;

	if( ip_check(tftp_arg.host) ){
		inet_aton(tftp_arg.host, (struct in_addr *)&(tftp_arg.server_addr.sin_addr));
	}
	else{
		if(wf_gethostbyname(tftp_arg.host, NULL, &tftp_arg.server_addr.sin_addr.s_addr) < 0){
			printf("unknown host [%s]\n", tftp_arg.host);
			return -1;
		}
	}
	tftp_arg.server_addr.sin_family =AF_INET;
	tftp_arg.server_addr.sin_port = htons(serverPort);
	
	socketfd = wf_udp_socket(tftp_arg.set_hport, 0, NULL);
	if(socketfd < 0){
		printf("socket error: %s\n", wf_socket_error(NULL));
		return -1;
	}

	if(!wf_buffer_malloc(&send_buffer, (unsigned int)tftp_arg.set_block_size))
		return -1;
	if(!wf_buffer_malloc(&recv_buffer, (unsigned int)tftp_arg.set_block_size))
		return -1;
	memset(&tftp_data, 0, sizeof(tftp_data));
	memset(&tftp_data_recv, 0, sizeof(tftp_data_recv));
	while(1)
	{
		memset(send_buffer.data, 0, send_buffer.size);
		ret = tftp_pack(&tftp_arg, &tftp_data, &send_buffer);
		if(ret < 0)
			goto END;

		ret = wf_sendto(socketfd, (unsigned char *)(send_buffer.data), send_buffer.len, 0, &tftp_arg.server_addr);
		if(ret <= 0){
			printf("sendto error: %s\n", wf_socket_error(NULL));
			goto END;
		}
		if(tftp_data.opcode == TFTP_ACK){
			++tftp_arg.block_id;
			if(tftp_arg.finished)
				break;
		}
		else if(tftp_data.opcode == TFTP_DATA)
			++tftp_arg.block_id;

		memset(recv_buffer.data, 0, recv_buffer.size);
		ret = tftp_recv(socketfd, &tftp_arg, &recv_buffer, 0);
		if(ret < 0)
			goto END;
		if(!ret)
			continue;

		//print_bytes((unsigned char *)(recv_buffer.data), (unsigned int)(recv_buffer.len));
		ret = tftp_unpack(&tftp_arg, &recv_buffer, &tftp_data_recv);
		if(ret < 0)
			goto END;

		if(tftp_arg.want_option_ack){
			tftp_arg.want_option_ack = 0;
			if(tftp_data_recv.opcode == TFTP_OACK){
				ch = tftp_option_get(tftp_data_recv.u.oack.data, tftp_data_recv.u.oack.len,"blksize");
				if(ch){
					new_set_block_size = atoi(ch);
					if(tftp_blocksize_check(new_set_block_size, tftp_arg.set_block_size - 4)){
						if(tftp_arg.tftp_cmd == TFTP_CMD_PUT)
							tftp_data.opcode = TFTP_DATA;
						else
							tftp_data.opcode = TFTP_ACK;
						tftp_arg.block_id = 0;
						ret = tftp_reset_send_buffer(&tftp_arg, new_set_block_size, &send_buffer);
						if(ret < 0)
							goto END;
					}

					continue;
				}
				
				printf("bad server option \n");
				ret = -1;
				goto END;
			}
			else{
				printf("warning: blksize not supported by server"" - reverting to %d \n", TFTP_BLOCKSIZE_DEFAULT);
				ret = tftp_reset_send_buffer(&tftp_arg, TFTP_BLOCKSIZE_DEFAULT, &send_buffer);
				if(ret < 0)
					goto END;
			}
		}
		
		if(tftp_data_recv.opcode == TFTP_ERROR){
			if((int)(tftp_data_recv.u.err.errcode) < (sizeof(tftp_bb_error_msg) / sizeof(char *)))
				printf("server say: [%d] %s \n", (int)(tftp_data_recv.u.err.errcode), tftp_bb_error_msg[(int)(tftp_data_recv.u.err.errcode)]);
			else
				printf("server say: [%d] %s \n", (int)(tftp_data_recv.u.err.errcode), tftp_data_recv.u.err.errmsg);
			ret = -1;
			goto END;
		}
		else if(tftp_data_recv.opcode == TFTP_ACK){
			//WFT_DEBUG("recv TFTP_ACK  tftp_arg.block_id=%d  recv_block_id=%d \n", tftp_arg.block_id, tftp_data_recv.u.ack.block);
			if(tftp_arg.block_id-1 == tftp_data_recv.u.ack.block){
				if(tftp_arg.finished){
					ret = 0;
					goto END;
				}
				tftp_data.opcode = TFTP_DATA;
				continue;
			}
		}
		else if(tftp_data_recv.opcode == TFTP_DATA){
			if(tftp_arg.block_id == tftp_data_recv.u.data.block){
				// write data to file
				ret = fwrite(tftp_data_recv.u.data.download, 1, tftp_data_recv.u.data.len, tftp_arg.localfp);
				if(ret < 0){
					printf("fwrite error: %s\n", wf_std_error(NULL));
					goto END;
				}
				else if(ret != tftp_arg.set_block_size - 4){
					++tftp_arg.finished;
				}
				
				tftp_data.opcode = TFTP_ACK;
				continue;
			}
			else if(tftp_arg.block_id - 1 == tftp_data_recv.u.data.block){
				tftp_arg.block_id -= 1;
				tftp_data.opcode = TFTP_ACK;
				continue;
			}
			else if(tftp_arg.block_id + 1 == tftp_data_recv.u.data.block){
				tftp_data.opcode = TFTP_ACK;
				continue;
			}
		}
	}

END:
	wf_buffer_free(&send_buffer, 0);
	wf_buffer_free(&recv_buffer, 0);
	tftp_t_free(&tftp_data_recv, 0);

	close(socketfd);
	if(tftp_arg.localfp)
		fclose(tftp_arg.localfp);

	if(tftp_arg.finished)
		return 0;
	else
		return ret;
}
/*
int cmd_tftpd(int argc, char **argv)
{
	int ret = 0;
	int socketfd = -1;
	char *ch = NULL;
	int serverPort = 69;
	
	struct tftp_t tftp_data, tftp_data_recv;
	struct wf_buffer send_buffer, recv_buffer;
}
*/
// ************************************   tftp     *********** end

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
	{"text", NULL, text_usage, cmd_text},
	{"qqrobot", NULL, NULL, cmd_qqrobot},
	{"tftpc", NULL, tftpc_usage, cmd_tftpc},
};

struct cmd_t *find_cmd(char *cmd)
{
	int idx = 0;

	for(idx=0; idx<ARRAY_NUM(cmd_list); idx++){
		if(strcmp(cmd, cmd_list[idx].cmd) == 0){
			return &cmd_list[idx];
		}
	}
	return NULL;
}

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
	
	if(cmd == NULL)
		wftool_usage();
	else{
		pcmd = find_cmd(cmd);
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
	char *p = NULL, *name = argv[0];
	int cmd_argc = argc;
	char **cmd_argv = argv;

	//printf("sid: %d  pgid: %d  pid: %d  ppid: %d \n", getsid(0), getpgid(0), getpid(), getppid());	
	p = name;
	while(*p != '\0'){
		if(*p == '/')
			name = p + 1;
		++p;
	}
	//WFT_DEBUG("name=[%s]\n", name);

	if(!strcmp(name, "wftool")){
		if(argc < 2 || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") ){
			wftool_usage();
			return 0;
		}
		else if( strcmp(argv[1], "help") == 0 )
			print_usage(argv[2]);
		else if(argv[2] && (!strcmp(argv[2], "-h") || !strcmp(argv[2], "--help")))
			print_usage(argv[1]);
		else{
			cmd_argc = argc -1;
			cmd_argv = argv + 1;
			goto FIND_CMD;
		}
	}
	else{
		if( !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") ){
			print_usage(name);
		}
	}

FIND_CMD:
	pcmd = find_cmd(cmd_argv[0]);
	if(!pcmd){
		wftool_usage();
		return 0;
	}

	if(pcmd->init_call){
		ret = pcmd->init_call(cmd_argc, cmd_argv);
		if(ret < 0){
			wfprintf("error: command init failed: %s \n", pcmd->cmd);
			return 1;
		}
	}
	if(pcmd->cmd_call){
		strcpy(print_name, pcmd->cmd);
		pcmd->cmd_call(cmd_argc, cmd_argv);
	}
	else
		wfprintf("error: can't execute %s \n", pcmd->cmd);

	return ret;
}

