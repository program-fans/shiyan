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

#include "libwf.h"

void wftool_usage()
{
	fprintf(stderr, "wftool usage: \n"
		"wftool ntorn [oldfile] [newfile] \n"
		"wftool rnton [oldfile] [newfile] \n"
		"wftool udp [send][recv][listen] [--ip] [--hport] [--dport] [--msg] [--pkt] \n"
		"wftool gethost [url] [url] [...] \n"
		);
}

int pipe_fd[2];

char asc_buf[4096] = {'\0'};

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


int cmd_ntorn(int argc, char **argv)
{
	FILE *fp_old, *fp_new;
	int len=0, i=1, tmp_len=0, line=0;

	fp_old = fopen(argv[++i], "r");
	if(fp_old == NULL)
	{
		printf("open old file error: %s \n", argv[i]);
		return -1;
	}
	fp_new = fopen(argv[++i], "w");
	if(fp_new == NULL)
	{
		printf("open new file error: %s \n", argv[i]);
		return -2;
	}

	while( fgets(asc_buf, sizeof(asc_buf), fp_old) != NULL )
	{
		++line;
		tmp_len = strlen(asc_buf);
		//printf("readline: %d len: %d [%d %d] \n", line, tmp_len, buf[tmp_len-2], buf[tmp_len-1]);
		if( asc_buf[tmp_len-1] == '\n' && asc_buf[tmp_len-2] != '\r' )
		{
			asc_buf[tmp_len-1] = '\r';
			asc_buf[tmp_len] = '\n';
			asc_buf[tmp_len+1] = '\0';
			//printf("writeline: %d len: %d \n", line, strlen(buf));
			fputs(asc_buf, fp_new);
		}
		else
		{
			//printf("writeline: %d len: %d \n", line, strlen(buf)    );
			fputs(asc_buf, fp_new);
		}
		memset(asc_buf, 0, sizeof(asc_buf));
	}
	printf("switch OK : %d lines \n", line);

	fclose(fp_old);
	fclose(fp_new);

	return 0;
}

int cmd_rnton(int argc, char **argv)
{
	FILE *fp_old, *fp_new;
	int len=0, i=1, tmp_len=0, line=0;

	fp_old = fopen(argv[++i], "r");
	if(fp_old == NULL)
	{
		printf("open old file error: %s \n", argv[i]);
		return -1;
	}
	fp_new = fopen(argv[++i], "w");
	if(fp_new == NULL)
	{
		printf("open new file error: %s \n", argv[i]);
		return -2;
	}

	while( fgets(asc_buf, sizeof(asc_buf), fp_old) != NULL )
	{
		++line;
		tmp_len = strlen(asc_buf);
		//printf("readline: %d len: %d [%d %d] \n", line, tmp_len, buf[tmp_len-2], buf[tmp_len-1]);
		if( asc_buf[tmp_len-1] == '\n' && asc_buf[tmp_len-2] == '\r' )
		{
			asc_buf[tmp_len-2] = '\n';
			asc_buf[tmp_len-1] = '\0';
			//printf("writeline: %d len: %d \n", line, strlen(buf));
			fputs(asc_buf, fp_new);
		}
		else
		{
			//printf("writeline: %d len: %d \n", line, strlen(buf)    );
			fputs(asc_buf, fp_new);
		}
		memset(asc_buf, 0, sizeof(asc_buf));
	}
	printf("switch OK : %d lines \n", line);

	fclose(fp_old);
	fclose(fp_new);

	return 0;
}

void cmd_udp(int argc, char **argv)
{
	int i=1, ret=0;
	int hport = 0, dport = 0, sport = 0, send = 1;
	int pkt = 1;
	int action = 0;	// 0: send; 1: recv; 2: listen
	char ip[16] = {'\0'};
	char msg[1024] = {'\0'};

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
		else{
			printf("invalid param: %s \n", argv[i]);
			return;
		}
	}

	switch(action)
	{
	default:
	case 0:		// send
		if(!ip_check(ip)){
			printf("invalid ip or not set: %s \n", ip);
			return;
		}
		if(dport <= 0 || dport > 65000){
			printf("invalid dport or not set: %d \n", dport);
			return;
		}
		ret = udp_send_ip(ip, hport, dport, (unsigned char *)msg, strlen(msg));
		if(ret > 0)
			printf("send OK: %d bytes \n", ret);
		else
			printf("error: %s \n", wf_socket_error(NULL));
		break;
	case 1:		// recv
		if(hport <= 0 || hport > 65000){
			printf("invalid hport: %d  or not set \n", hport);
			return;
		}
		ret = udp_recv_ip(hport, (unsigned char *)msg, sizeof(msg), ip, &sport);
		if(ret > 0){
			printf("recv OK: %d bytes from %s:%d \n", ret, ip, sport);
			printf("\t%s \n", msg);
		}
		else
			printf("error: %s \n", wf_socket_error(NULL));
		break;
	case 2:		// listen
		{
			int sock, pkt_cnt = 0, host_cnt = 0;
			unsigned long bytes_cnt = 0;
			char old_ip[16] = {'\0'};
			
			if(hport <= 0 || hport > 65000){
				printf("invalid hport: %d  or not set \n", hport);
				return;
			}
			sock = wf_udp_socket(hport);
			if(sock < 0){
				printf("error: %s \n", wf_socket_error(NULL));
				return;
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

int cmd_gethost(int argc, char **argv)
{
	int i = 1;
	char *arg;
	char *ptr, **pptr;
	struct hostent *hptr;
	char str[32];
	int ok_cnt=0, fail_cnt=0, all_cnt=0;
	
	while(1)
	{
		if(argv[2])
			arg = argv[++i];
		else
			arg = fgets(asc_buf, sizeof(asc_buf), stdin);
		if( !arg )
			break;
		wipe_off_CRLF_inEnd(arg);
		++all_cnt;
		
		if((hptr = gethostbyname(arg)) == NULL)
		{
			++fail_cnt;
			printf("error url: %s \n", arg);
			continue;
		}

		++ok_cnt;
		printf("url[%d]: %s \n", all_cnt, arg);
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
	}

	printf("stat: ok  %d   fail  %d \n", ok_cnt, fail_cnt);

	return 0;
}


int main(int argc, char **argv)
{
	int ret=0;

	if(argc >= 2)
	{
		if( strcmp(argv[1], "-h") == 0 )
			wftool_usage();
		else if( strcmp(argv[1], "ntorn") == 0 )
			ret = cmd_ntorn(argc, argv);
		else if( strcmp(argv[1], "rnton") == 0 )
			ret = cmd_rnton(argc, argv);
		else if( strcmp(argv[1], "udp") == 0 )
			cmd_udp(argc, argv);
		else if( strcmp(argv[1], "gethost") == 0 )
			ret = cmd_gethost(argc, argv);
		else
			wftool_usage();
	}
	else{
		wftool_usage();
	}

	return ret;
}

