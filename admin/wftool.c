#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <netdb.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include <fcntl.h>
#include <ctype.h>

#include <sys/time.h>

#include "libwf.h"


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


char asc_buf[4096] = {'\0'};
struct threadpool* thread_pool = NULL;

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
		"wftool udp [send][recv][listen] [--ip] [--hport] [--dport] [--msg] [--pkt] [--resp-pkt] \n"
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
void cmd_udp(int argc, char **argv)
{
	int i=1, ret=0;
	int hport = 0, dport = 0, sport = 0, send = 1;
	int pkt = 1;
	int action = 0;	// 0: send; 1: recv; 2: listen; 3: send-listen
	char ip[16] = {'\0'};
	char msg[1024] = {'\0'};
	int resp_pkt = 0;

	++i;
	if( strcmp(argv[i], "send") == 0 )
		action = 0;
	else if( strcmp(argv[i], "recv") == 0 )
		action = 1;
	else if( strcmp(argv[i], "listen") == 0 )
		action = 2;
	else
		--i;

	while(argv[++i])
	{
		if( strcmp(argv[i], "--ip") == 0 && argv[++i])
			strcpy(ip, argv[i]);
		else if( strcmp(argv[i], "--msg") == 0 && argv[++i])
			strcpy(msg, argv[i]);
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
				resp_pkt = 0;
			if(resp_pkt && action == 0)
				action = 3;
		}
		else{
			printf("invalid param: %s \n", argv[i]);
			return;
		}
	}

	switch(action)
	{
	default:
	case 0:		// send
		if( !udp_check_send(ip, dport, hport) )
			return;
		ret = udp_send_ip(ip, hport, dport, (unsigned char *)msg, strlen(msg));
		if(ret > 0)
			printf("send OK: %d bytes \n", ret);
		else
			printf("error: %s \n", wf_socket_error(NULL));
		break;
	case 1:		// recv
		if( !udp_check_recv(hport) )
			return;
		ret = udp_recv_ip(hport, (unsigned char *)msg, sizeof(msg), ip, &sport);
		if(ret > 0){
			printf("recv OK: %d bytes from %s:%d \n", ret, ip, sport);
			printf("\t%s \n", msg);
		}
		else
			printf("error: %s \n", wf_socket_error(NULL));
		break;
	case 2:		// listen
	case 3:		// send-listen
		{
			int sock, pkt_cnt = 0, host_cnt = 0;
			unsigned long bytes_cnt = 0;
			char old_ip[16] = {'\0'};

			if(action == 2){
				if( !udp_check_recv(hport) )
					return;
			}
			else if(action == 3){
				if( !udp_check_send(ip, dport, hport) )
					return;
			}
			
			sock = wf_udp_socket(hport, 0, NULL);
			if(sock < 0){
				printf("error: %s \n", wf_socket_error(NULL));
				return;
			}

			if(action == 3){
				ret = wf_sendto_ip(sock, (unsigned char *)msg, strlen(msg), 0,ip, dport);
				if(ret > 0)
					printf("send OK: %d bytes \n", ret);
				else
					printf("error: %s \n", wf_socket_error(NULL));
				memset(ip, 0, sizeof(ip));
				memset(msg, 0, sizeof(msg));
				printf("-------------------------------------\n");
			}

			while(pkt)
			{
				strcpy(old_ip, ip);
				ret = wf_recvfrom_ip(sock, (unsigned char *)msg, sizeof(msg), 0, ip, &sport);
				if(ret > 0){
					++pkt_cnt; --pkt; bytes_cnt += ret;
					if( strcmp(old_ip, ip) )
						++host_cnt;
					printf("recv OK: %d bytes from %s:%d  [pkt: %d]\n", ret, ip, sport, pkt_cnt);
					printf("\t%s \n", msg);
				}
				else{
					printf("error: %s \n", wf_socket_error(NULL));
					//return;
				}
			}
			close(sock);
			printf("recv finish: %lu bytes  %d packets  from %d hosts \n", bytes_cnt, pkt_cnt, host_cnt);
		}
		break;
	}

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
		printf("localtime: %04d.%02d.%02d-%02d:%02d:%02d \n", 
			local_time->tm_year+1900, local_time->tm_mon+1, local_time->tm_mday,
			local_time->tm_hour, local_time->tm_min, local_time->tm_sec);
	}

	return 0;
}

void wftool_usage()
{
	fprintf(stderr, "wftool usage: \n"
		"\twftool [cmd] [option] [...] \n"
		"cmd list: \n"
		"  help \n"
		"  txt \n"
		"  udp \n"
		"  gethost \n"
		"  asc \n"
		"  wol \n"
		"  time \n"
		"note:\"wftool help <cmd>\" for help on a specific cmd \n"
		);
}

void print_usage(char *cmd)
{
	if(cmd == NULL)
		wftool_usage();
	else if( strcmp(cmd, "udp") == 0 )
		udp_usage();
	else if( strcmp(cmd, "gethost") == 0 )
		gethost_usage();
	else if( strcmp(cmd, "asc") == 0 )
		asc_usage();
	else if( strcmp(cmd, "wol") == 0 )
		wol_usage();
	else if( strcmp(cmd, "txt") == 0 )
		txt_usage();
	else if( strcmp(cmd, "time") == 0 )
		time_usage();
	else
		wftool_usage();
}

int main(int argc, char **argv)
{
	int ret=0;

	if(argc >= 2)
	{
		if( strcmp(argv[1], "-h") == 0 )
			wftool_usage();
		else if( strcmp(argv[1], "help") == 0 )
			print_usage(argv[2]);
		else if( strcmp(argv[1], "ntorn") == 0 )
			ret = cmd_ntorn(argc, argv);
		else if( strcmp(argv[1], "rnton") == 0 )
			ret = cmd_rnton(argc, argv);
		else if( strcmp(argv[1], "a1torn") == 0 )
			ret = cmd_a1torn(argc, argv);
		
		else if( strcmp(argv[1], "udp") == 0 )
			cmd_udp(argc, argv);
		else if( strcmp(argv[1], "gethost") == 0 )
			ret = cmd_gethost(argc, argv);
		else if( strcmp(argv[1], "asc") == 0 )
			ret = cmd_asc(argc, argv);
		else if( strcmp(argv[1], "wol") == 0 )
			ret = cmd_wol(argc, argv);
		else if( strcmp(argv[1], "time") == 0 )
			ret = cmd_time(argc, argv);
		else
			wftool_usage();
	}
	else{
		wftool_usage();
	}

	return ret;
}

