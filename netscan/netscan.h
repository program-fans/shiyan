#ifndef NETSCAN_H_
#define NETSCAN_H_

#include "libwf.h"

enum SCAN_FLAG
{
	SCAN_FLAG_ADDR_CONTINUE,		// continuous addr
	SCAN_FLAG_ADDR_DISCONTINUE,		// discontinuous addr
	SCAN_FLAG_PORT_CONTINUE,			// continuous port
	SCAN_FLAG_PORT_DISCONTINUE,		// discontinuous port
	SCAN_FLAG_NO_PORT,				// no port
	SCAN_FLAG_ASCEND,					// ascending port sequence
	SCAN_FLAG_DESCEND,				// descending port sequence
	SCAN_FLAG_RANDOM					// random port sequence
};

struct netscan_t
{
	unsigned int saddr;
	unsigned int eaddr;
	unsigned short sport;
	unsigned short eport;
	unsigned int *addr;
	unsigned int addr_num;
	unsigned short *port;
	unsigned int port_num;
	unsigned long flags;		// enum SCAN_FLAG
};

extern int netscan_check(struct netscan_t *scan);

extern int netscan_addr_random(struct netscan_t *scan);

extern int netscan_port_random(struct netscan_t *scan);

extern int netscan_done(struct netscan_t *scan, void *arg, int (*proc)(unsigned int addr, unsigned short port, void *arg));

extern int netscan_get_targe_num(struct netscan_t *scan);

extern void netscan_t_print(struct netscan_t *scan);

struct addr_port
{
	unsigned int addr;
	unsigned short port;
	struct slist_node slist;
};

struct netscan_result
{
	int type;				// 0: off;  1: on
	unsigned int num;
	pthread_mutex_t list_lock;
	struct slist_head addr_port_list;
};

extern int netscan_result_init(struct netscan_result *result, int type);

extern int netscan_result_destory(struct netscan_result *result, int free_self);

extern int save_addr_port(struct netscan_result *result, unsigned int addr, unsigned short port);


extern char *ttl_2_os_type(unsigned char ttl, char *os_type, unsigned int size);


extern int netscan_arg_parse(int argc, char **argv, int *new_argc, char **new_argv, struct netscan_t *scan);

#endif
