#ifndef PEEK_H_
#define PEEK_H_

#include <time.h>

#include "linux_list.h"
/*
struct match_app
{
	char name[32];
	int match_num;
	void *matchs[10];
	int conn_num;
	void *conns[20];
	struct list_head match_app_head;
};*/

struct conn_match_data
{
	int start;
	int end;
	int len;
	unsigned char info[1024];
};

enum CONNMATCH_FLAG
{
	MATCH_FLAG_INVAILD,
	MATCH_FLAG_PROTO,
	MATCH_FLAG_SRC,
	MATCH_FLAG_DST_IP,
	MATCH_FLAG_DST_PORT,
	MATCH_FLAG_HOST,
	MATCH_FLAG_DATA,
	MATCH_FLAG_MAX
};

struct conn_match_t
{
	char name[32];
	unsigned long flag;
	unsigned char protonum;
	unsigned short port_src;
	unsigned int ip_dst;
	unsigned short port_dst;
	char host_buf[256];
	char *host;
	struct conn_match_data data;
	struct list_head match_head;
};

struct conn_match_list
{
	int count;
	struct list_head match_list_head;
};

#define conntrack_hash_table_size		8

struct conntrack_hash_table
{
	unsigned int count;
	unsigned int list_counts[conntrack_hash_table_size];
	struct list_head kv_head[conntrack_hash_table_size];
};

enum conntrack_status
{
	CONN_STATUS_NEW,
	CONN_STATUS_CONFIRM,
	CONN_STATUS_HANDS_3,
	CONN_STATUS_HANDS_4,
	CONN_STATUS_REPLAY,
	CONN_STATUS_LONG,					// long connect
	CONN_STATUS_TIMEOUT,
	CONN_STATUS_CLOSE
};

struct conntrack_tuple
{
	unsigned int ip_src;
	unsigned int ip_dst;
	unsigned short port_src;
	unsigned short port_dst;
	unsigned char protonum;
};

struct conntrack_t
{
	struct conntrack_tuple *tuple;
	struct conntrack_tuple tuple_replay;
	unsigned long status;
	int hash_key;
	struct list_head hash_head;
	int timer;
	long last_time;
	long insert_time;
	time_t start_time;				// absolute time
	char host_buf[256];
	char *host;
	struct conn_match_t *match;
	struct conntrack_t *me;
};

struct peek_t
{
	int enable;
	struct conntrack_hash_table conn_hash_table;
	struct conn_match_list match_list;
};


void peek_init();

void peek_close();

void peek_enable();

void peek_disEnable();

void peek(unsigned char *buf, int len);

void peek_print();

void clean_timeout_conn();

void peek_loop_1(long now);

void peek_loop_2(long now);

int read_match(char *file);

void print_matchlist();

#endif

