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

#include "wftool.h"

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

int cmd_tftpc(int argc, char **argv)
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
	
	ret = arg_parse(argc, argv, cmd_tftp_arg_list, &wf_argc, wf_argv);
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

