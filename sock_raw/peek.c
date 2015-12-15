#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libwf.h"

#include "net_monitor.h"
#include "peek.h"

struct peek_t g_peek;
MemPool *conntrack_tuple_pool;
MemPool *conntrack_t_pool;
MemPool *connmatch_t_pool;
char match_flag_str[MATCH_FLAG_MAX][16]={"invalid", "proto", "src", "dst_ip", "dst_port", "host", "data"};

void free_conn(struct conntrack_t *conn);
void free_match(struct conn_match_t *match);

void peek_init()
{
	int i;
	
	memset(&g_peek, 0, sizeof(g_peek));
	for(i=0; i<conntrack_hash_table_size; i++)
		INIT_LIST_HEAD(&g_peek.conn_hash_table.kv_head[i]);
	INIT_LIST_HEAD(&g_peek.match_list.match_list_head);
	
	conntrack_tuple_pool = new_mem_pool(256, sizeof(struct conntrack_tuple), Mod_NO_MemId);
	conntrack_t_pool = new_mem_pool(256, sizeof(struct conntrack_t), Mod_NO_MemId);
	connmatch_t_pool = new_mem_pool(256, sizeof(struct conn_match_t), Mod_NO_MemId);
}

void peek_enable()
{
	g_peek.enable = 1;
	timerTaskStart(1);
}

void peek_disEnable()
{
	g_peek.enable = 0;
}

void peek_close()
{
	int i;
	struct list_head *list;
	struct conntrack_t *pos, *n;
	struct conn_match_t *mpos, *mn;
	
	peek_disEnable();
	//sleep(1);
	
	if(g_peek.conn_hash_table.count == 0)
		goto FREE_MATCH;
	
	for(i=0; i<conntrack_hash_table_size; i++)
	{
		list = &g_peek.conn_hash_table.kv_head[i];
		if(list_empty_careful(list))
			continue;
		list_for_each_entry_safe(pos, n, list, hash_head)
		{
			list_del_init(&pos->hash_head);
			free_conn(pos);
		}
	}
	
FREE_MATCH:
	list = &g_peek.match_list.match_list_head;
	if(list_empty_careful(list))
		goto FREE_POOL;
	list_for_each_entry_safe(mpos, mn, list, match_head)
	{
		list_del_init(&mpos->match_head);
		free_match(mpos);
	}
	
FREE_POOL:	
	free_mem_pool(conntrack_tuple_pool);
	free_mem_pool(conntrack_t_pool);
	free_mem_pool(connmatch_t_pool);

	timerTaskStart(0);
}

void peek_print()
{
	int i;
	struct list_head *list;
	struct conntrack_t *pos;
	
	if(g_peek.enable)
	{
		printf("-------- peek ------------\n");
		if(g_peek.conn_hash_table.count)
		{
			printf("count: %u \n", g_peek.conn_hash_table.count);
			for(i=0; i<conntrack_hash_table_size; i++)
				printf("%u  ", g_peek.conn_hash_table.list_counts[i]);
			printf("\n");

			for(i=0; i<conntrack_hash_table_size; i++)
			{
				list = &g_peek.conn_hash_table.kv_head[i];
				if(list_empty_careful(list))
					continue;
				list_for_each_entry(pos, list, hash_head)
				{
					printf("src[%s:%u] ", (char *)inet_ntoa(pos->tuple->ip_src), ntohs(pos->tuple->port_src));
					printf("dst[%s:%u] proto[%u] replay[%s] %s %s %s %s  [%lu s]\n", 
						(char *)inet_ntoa(pos->tuple->ip_dst), ntohs(pos->tuple->port_dst), 
						pos->tuple->protonum, 
						test_bit(CONN_STATUS_REPLAY, &pos->status) ? "yes" : "no", 
						test_bit(CONN_STATUS_HANDS_3, &pos->status) ? "hand-3" : "", 
						test_bit(CONN_STATUS_HANDS_4, &pos->status) ? "hand-4" : "", 
						test_bit(CONN_STATUS_TIMEOUT, &pos->status) ? "TIMEOUT" : "", 
						test_bit(CONN_STATUS_CLOSE, &pos->status) ? "CLOSE" : "", 
						pos->last_time - pos->insert_time);
					if(pos->host)
						printf("  %s \n", pos->host);
					if(pos->match)
						printf("match: %s \n", pos->match->name);
				}
			}
		}
		else
			printf("nothing \n");

		printf("-----------------------------\n");
	}
	else
		printf("peek: disenable \n");
}

struct conn_match_t *new_match()
{
	struct conn_match_t *match = borrow_mem_type(connmatch_t_pool, struct conn_match_t, NULL);

	if(match)
	{
		memset(match, 0, sizeof(struct conn_match_t));
		INIT_LIST_HEAD(&match->match_head);
	}
	else
		printf("no free match use[%u] free[%u] \n", get_use_mem_num(connmatch_t_pool), get_free_mem_num(connmatch_t_pool));
	
	return match;
}

void free_match(struct conn_match_t *match)
{
	restore_mem(connmatch_t_pool, match, 0, sizeof(struct conn_match_t));
}

void insert_match(struct conn_match_t *match)
{
	list_add(&match->match_head, &g_peek.match_list.match_list_head);
	++g_peek.match_list.count;
}

void print_match(struct conn_match_t *match)
{
	char buf[2048]={'\0'};
	printf("name: %s \n", match->name);
	printf("flag: %lx \n", match->flag);
	printf("protonum: %d \n", match->protonum);
	printf("port_src: %u \n", ntohs(match->port_src));
	printf("ip_dst: %s \n", (char *)inet_ntoa(match->ip_dst));
	printf("port_dst: %u \n", ntohs(match->port_dst));
	printf("host: %s \n", match->host ? match->host : "null");
	printf("start: %d;  end: %d \n", match->data.start, match->data.end);
	bcd2asc(buf, match->data.info, match->data.len);
	printf("info: %s \n", buf);
}
void print_matchlist()
{
	struct conn_match_t *pos;
	
	printf("--------- match list ---------\n");
	if( !list_empty_careful(&g_peek.match_list.match_list_head) )
	{
		list_for_each_entry(pos, &g_peek.match_list.match_list_head, match_head)
		{
			print_match(pos);
			printf("\n");
		}
	}
	printf("---------------------------------\n");
}

void json_to_matchlist(cJSON *root)
{
	cJSON *obj, *json_tmp, *json_flag, *json_data;
	int i, j, k, num, jnum;
	struct conn_match_t *match;
	
	if(root->type != cJSON_Array)
		return;
	num = cJSON_GetArraySize(root);
	for(i=0; i<num; i++)
	{
		obj = cJSON_GetArrayItem(root, i);
		if(obj==NULL)
			continue;
		match = new_match();
		if(match == NULL)
			break;
		
		json_tmp = cJSON_GetObjectItem(obj, "name");
		if(json_tmp)
			strcpy(match->name, json_tmp->valuestring);
		else
			sprintf(match->name, "match_%d", i);

		json_tmp = cJSON_GetObjectItem(obj, "flag");
		if(json_tmp && json_tmp->type == cJSON_Array)
		{
			jnum  = cJSON_GetArraySize(json_tmp);
			for(j=0; j<jnum; j++)
			{
				json_flag = cJSON_GetArrayItem(json_tmp, j);
				if(json_flag == NULL)
					continue;
				for(k=0; k<MATCH_FLAG_MAX; k++)
				{
					if( json_flag->valuestring && strcmp(json_flag->valuestring, match_flag_str[k]) == 0 )
						set_bit(k, &match->flag);
				}
			}
		}
		else
			goto ERR_FREE_MATCH;
		
		if(test_bit(MATCH_FLAG_PROTO, &match->flag))
		{
			json_tmp = cJSON_GetObjectItem(obj, "proto");
			if(json_tmp)
			{
				if( strcmp(json_tmp->valuestring, "udp")==0 )
					match->protonum = IPPROTO_UDP;
				else if( strcmp(json_tmp->valuestring, "tcp")==0 )
					match->protonum = IPPROTO_TCP;
				else
					match->protonum = 0;
			}
			else
				goto ERR_FREE_MATCH;
		}
		
		if(test_bit(MATCH_FLAG_SRC, &match->flag))
		{
			json_tmp = cJSON_GetObjectItem(obj, "src");
			if(json_tmp)
				match->port_src = htons(json_tmp->valueint);
			else
				goto ERR_FREE_MATCH;
		}
		
		if(test_bit(MATCH_FLAG_DST_IP, &match->flag))
		{
			json_tmp = cJSON_GetObjectItem(obj, "dst_ip");
			if(json_tmp)
			{
				if( inet_aton(json_tmp->valuestring, (struct in_addr *)&match->ip_dst) == 0 )
					goto ERR_FREE_MATCH;
			}
			else
				goto ERR_FREE_MATCH;
		}
		
		if(test_bit(MATCH_FLAG_DST_PORT, &match->flag))
		{
			json_tmp = cJSON_GetObjectItem(obj, "dst_port");
			if(json_tmp)
				match->port_src = htons(json_tmp->valueint);
			else
				goto ERR_FREE_MATCH;
		}
		
		if(test_bit(MATCH_FLAG_HOST, &match->flag))
		{
			json_tmp = cJSON_GetObjectItem(obj, "host");
			if(json_tmp)
			{
				strcpy(match->host_buf, json_tmp->valuestring);
				match->host = match->host_buf;
			}
			else
				goto ERR_FREE_MATCH;
		}
		
		if(test_bit(MATCH_FLAG_DATA, &match->flag))
		{
			json_tmp = cJSON_GetObjectItem(obj, "data");
			if(json_tmp)
			{
				json_data = cJSON_GetObjectItem(json_tmp, "start");
				if(json_data && json_data->valueint > 0)
					match->data.start = json_data->valueint;
				else
					match->data.start = 0;
				
				json_data = cJSON_GetObjectItem(json_tmp, "end");
				if(json_data && json_data->valueint > 0)
					match->data.end = json_data->valueint;
				else
					goto ERR_FREE_MATCH;
				
				match->data.len = match->data.end - match->data.start + 1;
				if(match->data.len < 0 || match->data.len > 1024)
					goto ERR_FREE_MATCH;
				
				json_data = cJSON_GetObjectItem(json_tmp, "info");
				if(json_data)
					asc2bcd(match->data.info, json_data->valuestring, strlen(json_data->valuestring));
				else
					goto ERR_FREE_MATCH;
			}
			else
				goto ERR_FREE_MATCH;
		}

		INIT_LIST_HEAD(&match->match_head);
		insert_match(match);
		continue;
		
	ERR_FREE_MATCH:
		free_match(match);
	}
}

int read_match(char *file)
{
	FILE *fp=NULL;
	long size;
	char *buf = NULL;
	cJSON *root = NULL;
	size_t r_read;

	if(file == NULL)
		return -1;

	fp = fopen(file,"r");
	if(fp == NULL)
	{
		printf("open error \n");
		return -1;
	}
	
	fseek(fp, 0, SEEK_END);
	size = ftell(fp);

	buf = (char *)malloc(size+1);
	if(buf == NULL)
	{
		printf("malloc error \n");
		goto ERR_END;
	}
	memset(buf, 0, size+1);

	fseek(fp, 0, SEEK_SET);
	r_read = fread(buf, 1, size, fp);
	//printf("size: %ld  read: %d \n", size, r_read);
	//printf("%s\n", buf);
	if( r_read <  0 )
	{
		printf("read error [%s]\n", strerror(ferror(fp)));
		goto ERR_END;
	}
	else if(r_read ==  0)
	{
		printf("file is empty [%d]\n", ferror(fp));
		goto ERR_END;
	}
	buf[r_read] = '\0';

	root = cJSON_Parse(buf);
	if(root == NULL)
	{
		printf("cJSON_Parse error \n");
		goto ERR_END;
	}
	
	json_to_matchlist(root);

	free(buf);
	fclose(fp);
	cJSON_Delete(root);
	return 0;

ERR_END:
	if(buf)	free(buf);
	if(fp)	fclose(fp);
	if(root)	cJSON_Delete(root);
	return -1;
}

struct conntrack_tuple *new_conn_tuple(struct iphdr *iph)
{
	struct conntrack_tuple *tuple = borrow_mem_type(conntrack_tuple_pool, struct conntrack_tuple, NULL);
	
	if(tuple)
	{
		memset(tuple, 0, sizeof(struct conntrack_tuple));
		tuple->ip_src = iph->saddr;
		tuple->ip_dst = iph->daddr;
		tuple->protonum = iph->protocol;
	}
	else
		printf("no free tuple use[%u] free[%u] \n", get_use_mem_num(conntrack_tuple_pool), get_free_mem_num(conntrack_tuple_pool));
	
	return tuple;
}

void free_conn_tuple(struct conntrack_tuple *tuple)
{
	restore_mem(conntrack_tuple_pool, tuple, 0, sizeof(struct conntrack_tuple));
}

void tuple_print(struct conntrack_tuple *tuple)
{
	printf("src[%s:%u] ", (char *)inet_ntoa(tuple->ip_src), ntohs(tuple->port_src));
	printf("dst[%s:%u] proto[%u]\n", (char *)inet_ntoa(tuple->ip_dst), ntohs(tuple->port_dst), 
		tuple->protonum);
}

void tuple_to_replay(struct conntrack_tuple *tuple, struct conntrack_tuple *tuple_replay)
{
	tuple_replay->ip_dst = tuple->ip_src;
	tuple_replay->ip_src = tuple->ip_dst;
	tuple_replay->port_dst = tuple->port_src;
	tuple_replay->port_src = tuple->port_dst;
	tuple_replay->protonum = tuple->protonum;
}

struct conntrack_t *new_conn(struct conntrack_tuple *tuple)
{
	struct conntrack_t *conn = borrow_mem_type(conntrack_t_pool, struct conntrack_t, NULL);
	if(conn)
	{
		memset(conn, 0, sizeof(struct conntrack_t));
		conn->tuple = tuple;
		conn->hash_key = tuple_to_hashkey(tuple);
		set_bit(CONN_STATUS_NEW, &conn->status);
		tuple_to_replay(tuple, &conn->tuple_replay);
		INIT_LIST_HEAD(&conn->hash_head);
		conn->me = conn;
	}
	else
		printf("no free conn \n");

	return conn;
}

void free_conn(struct conntrack_t *conn)
{
	if(conn->timer > 0)
		timerStop(conn->timer);
	conn->timer = 0;
	if(conn->tuple)
		free_conn_tuple(conn->tuple);
	conn->tuple = NULL;
	conn->me = NULL;
	restore_mem(conntrack_t_pool, conn, 0, sizeof(struct conntrack_t));
}

struct conntrack_t *find_conn(int hashKey, struct conntrack_tuple *tuple, int set_replay)
{
	struct conntrack_t *pos;

	if(list_empty_careful(&g_peek.conn_hash_table.kv_head[hashKey]))
		return NULL;
	list_for_each_entry(pos, &g_peek.conn_hash_table.kv_head[hashKey], hash_head)
	{
		if(test_bit(CONN_STATUS_CLOSE, &pos->status))
			continue;
		if(memcmp(pos->tuple, tuple, sizeof(struct conntrack_tuple)) == 0)
			return pos;

		if( memcmp(&pos->tuple_replay, tuple, sizeof(struct conntrack_tuple)) == 0 )
		{
			if( set_replay && !test_bit(CONN_STATUS_REPLAY, &pos->status) )
				set_bit(CONN_STATUS_REPLAY, &pos->status);
			return pos;
		}
	}

	return NULL;
}

int conn_timeout(void *c, int size)
{
	struct conntrack_t **pconn = (struct conntrack_t **)c;
	struct conntrack_t *conn = *pconn;
	long now;

	if(!g_peek.enable)
		return 0;

	if(test_bit(CONN_STATUS_TIMEOUT, &conn->status))
		return 0;

	now = get_system_uptime(NULL);
	if(now > (conn->last_time + 20))
		set_bit(CONN_STATUS_TIMEOUT, &conn->status);

	return 0;
}

void insert_conn(struct conntrack_t *conn)
{
	list_add(&conn->hash_head, &g_peek.conn_hash_table.kv_head[conn->hash_key]);
	conn->insert_time = get_system_uptime(NULL);
	set_bit(CONN_STATUS_CONFIRM, &conn->status);
	++g_peek.conn_hash_table.count;
	++g_peek.conn_hash_table.list_counts[conn->hash_key];
	conn->timer = timerAdd(2, conn_timeout, &conn, sizeof(struct conntrack_t *), 1);
}

void clean_timeout_conn()
{
	int i;
	struct list_head *list;
	struct conntrack_t *pos, *n;
	
	if(!g_peek.enable)
		return;
	if(g_peek.conn_hash_table.count == 0)
		return;
	
	for(i=0; i<conntrack_hash_table_size; i++)
	{
		list = &g_peek.conn_hash_table.kv_head[i];
		if(list_empty_careful(list))
			continue;
		list_for_each_entry_safe(pos, n, list, hash_head)
		{
			if(test_bit(CONN_STATUS_TIMEOUT, &pos->status) || test_bit(CONN_STATUS_CLOSE, &pos->status))
			{
				list_del_init(&pos->hash_head);
				--g_peek.conn_hash_table.count;
				--g_peek.conn_hash_table.list_counts[i];
				free_conn(pos);
			}
		}
	}
}

int tuple_to_hashkey(struct conntrack_tuple *tuple)
{
	unsigned int a, d, e, f;
	//unsigned short b;
	unsigned char c;

	a = tuple->ip_src / conntrack_hash_table_size;
	a += tuple->ip_dst / conntrack_hash_table_size;
	
	e = (unsigned int)ntohs(tuple->port_src);
	f = (unsigned int)ntohs(tuple->port_dst);

	c = tuple->protonum / conntrack_hash_table_size;

	d = a + e + f;
	d += (unsigned int)c;

	d = d % conntrack_hash_table_size;

	return (int)d;
}

void peek_match(unsigned char *buf, int len, struct conntrack_t *conn)
{
	struct conn_match_t *pos;

	if(conn->match)
		return;
	
	if(list_empty_careful(&g_peek.match_list.match_list_head))
		return;
	list_for_each_entry(pos, &g_peek.match_list.match_list_head, match_head)
	{
		if(test_bit(MATCH_FLAG_INVAILD, &pos->flag))
			continue;
		if(test_bit(MATCH_FLAG_PROTO, &pos->flag) && pos->protonum != conn->tuple->protonum)
			continue;
		if(test_bit(MATCH_FLAG_SRC, &pos->flag) && pos->port_src != conn->tuple->port_src)
			continue;
		if(test_bit(MATCH_FLAG_DST_IP, &pos->flag) && pos->port_src != conn->tuple->ip_dst)
			continue;
		if(test_bit(MATCH_FLAG_DST_PORT, &pos->flag) && pos->port_src != conn->tuple->port_dst)
			continue;
		if(test_bit(MATCH_FLAG_HOST, &pos->flag))
		{
			if(conn->host == NULL || pos->host == NULL)
				continue;
			if(strcmp(conn->host, pos->host) != 0)
				continue;
		}
		if(test_bit(MATCH_FLAG_DATA, &pos->flag))
		{
			if(pos->data.start >= len || pos->data.end >= len)
				continue;
			if(memcmp(pos->data.info, buf+pos->data.start, pos->data.len) != 0)
				continue;
		}
		conn->match = pos;
		break;
	}
}

void peek_http(unsigned char *buf, int len, struct conntrack_t *conn)
{
	char *ptr = (char *)buf;
	char *p, *p2;
	char tmp_buf[256]={'\0'};
	unsigned int a;
	
	if(conn->tuple->protonum != IPPROTO_TCP)
		return;
	if(ntohs(conn->tuple->port_dst) != HTTP_PORT && ntohs(conn->tuple->port_src) != HTTP_PORT)
		return;
// host	
	if(conn->host)
			goto NEXT;
	if( strncmp(ptr, HTTP_REQ_GET, strlen(HTTP_REQ_GET)) == 0 
		|| strncmp(ptr, HTTP_REQ_POST, strlen(HTTP_REQ_GET)) == 0 )
	{
		p = strstr(ptr, "\r\n\r\n");
		if(!p)
			goto NEXT;
		p2 = strstr(ptr, "Host:");
		if(!p2 || p2 > p)
			goto NEXT;
		p = strstr(p2, "\r\n");
		if(!p)
			goto NEXT;
		p2 += 5;
		while(*p2 == ' ' || *p2 == '\t')	++p2;
		if(p2 == p)
			goto NEXT;
		a = p - p2;
		strncpy(conn->host_buf, p2, a);
		conn->host = conn->host_buf;
	}
	
NEXT:
	return;
}

void peek_level_5(unsigned char *buf, int len, struct conntrack_t *conn)
{
	if(conn == NULL || buf == NULL || len < 1)
		return;

	if(!test_bit(CONN_STATUS_LONG, &conn->status))
	{
		if(conn->last_time - conn->insert_time > 60)
			set_bit(CONN_STATUS_LONG, &conn->status);
	}

	peek_http(buf, len, conn);
	peek_match(buf, len, conn);
	
	return;
}
	
void peek_level_tcp(unsigned char *buf, int len, struct conntrack_tuple *tuple)
{
	struct tcphdr *tcph;
	int hlen;
	int key;
	struct conntrack_t *conn;
	
	if(tuple == NULL || buf == NULL || len < sizeof(struct tcphdr))
		return;
	tcph = (struct tcphdr *)buf;
	hlen = (int)(tcph->doff * 4);
	tuple->port_src = tcph->source;
	tuple->port_dst = tcph->dest;
	key = tuple_to_hashkey(tuple);
	//tuple_print(tuple);
	conn = find_conn(key, tuple, 1);
	if(!conn)
	{
		//printf("key=%d, not find \n", key);
		conn = new_conn(tuple);
		if(!conn)
			goto FREE_TUPLE;
		insert_conn(conn);
	}
	else
	{
		//printf("key=%d, find \n", key);
		free_conn_tuple(tuple);
	}

	if(tcph->ack && !tcph->syn && !tcph->fin && !test_bit(CONN_STATUS_HANDS_3, &conn->status))
		set_bit(CONN_STATUS_HANDS_3, &conn->status);
	if(tcph->fin && !test_bit(CONN_STATUS_HANDS_4, &conn->status))
		set_bit(CONN_STATUS_HANDS_4, &conn->status);

	conn->last_time = get_system_uptime(NULL);
	peek_level_5(buf + hlen, len - hlen, conn);
	return;

FREE_TUPLE:
	free_conn_tuple(tuple);
}

void peek_level_udp(unsigned char *buf, int len, struct conntrack_tuple *tuple)
{
	struct udphdr *udph;
	int key;
	struct conntrack_t *conn;
	
	if(tuple == NULL || buf == NULL || len < sizeof(struct udphdr))
		return;
	udph = (struct udphdr *)buf;
	tuple->port_src = udph->source;
	tuple->port_dst = udph->dest;
	key = tuple_to_hashkey(tuple);
	conn = find_conn(key, tuple, 1);
	if(!conn)
	{
		conn = new_conn(tuple);
		if(!conn)
			goto FREE_TUPLE;
		insert_conn(conn);
	}
	else
		free_conn_tuple(tuple);

	

	conn->last_time = get_system_uptime(NULL);
	peek_level_5(buf + sizeof(struct udphdr), len - sizeof(struct udphdr), conn);
	return;

FREE_TUPLE:
	free_conn_tuple(tuple);
}

void peek_level_3(unsigned char *buf, int len)
{	
	struct iphdr *iph;
	int hlen;
	struct conntrack_tuple *tuple = NULL;

	if(buf == NULL || len < sizeof(struct iphdr))
		return;
	iph = (struct iphdr *)buf;
	hlen = (int)(iph->ihl * 4);
	
	
	if( iph->protocol == IPPROTO_TCP )
	{
		tuple = new_conn_tuple(iph);
		peek_level_tcp(buf + hlen, len - hlen, tuple);
	}
	else if( iph->protocol == IPPROTO_UDP )
	{
		tuple = new_conn_tuple(iph);
		peek_level_udp(buf + hlen, len - hlen, tuple);
	}
}

void peek_level_2(unsigned char *buf, int len)
{
	struct ethhdr *eth;
	unsigned short proto;
	
	if(buf == NULL || len < sizeof(struct ethhdr))
		return;
	eth = (struct ethhdr *)buf;
	proto = ntohs(eth->h_proto);
	

	if( proto != ETH_P_IP)
		return;

	peek_level_3(buf + sizeof(struct ethhdr), len - sizeof(struct ethhdr));
}

void peek(unsigned char *buf, int len)
{
	if( !g_peek.enable )
		return;
	
	peek_level_2(buf, len);
}

void peek_loop_1(long now)
{
	static long last=0;

	if( !g_peek.enable )
		return;

	if(last == 0 || now >= last)
	{
		last = now+2;
		peek_print();
	}
}

void peek_loop_2(long now)
{
	static long last=0;

	if( !g_peek.enable )
		return;

	if(last == 0 || now >= last)
	{
		last = now+5;
		clean_timeout_conn();
	}
}

