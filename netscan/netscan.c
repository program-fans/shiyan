#include <stdio.h>
#include <stdlib.h>

#include "netscan.h"

#if 0
void bubble_sort_port(unsigned short *num, int start_index, int end_index, int is_ascend)
{
	int i, j;
	unsigned short k;
	
	for(i=start_index+1; i<end_index; i++){
		for(j=start_index; j<end_index+1+start_index-i; j++){
			if((is_ascend && num[j] > num[j+1]) || (!is_ascend && num[j] < num[j+1])){
				k = num[j];
				num[j] = num[j+1];
				num[j+1] = k;
			}
		}
	}
}
#else
void bubble_sort_port(unsigned short *num, int start_index, int end_index, int is_ascend)
{
	int i, j;
	unsigned short k;
	
	for(i=start_index+1; i<end_index; i++){
		for(j=start_index; j<end_index+1+start_index-i; j++){
			if(num[j] > num[j+1]){
				k = num[j];
				num[j] = num[j+1];
				num[j+1] = k;
			}
		}
	}

	if(!is_ascend){
		j = (1 + end_index - start_index) / 2;
		for(i=0; i<j; i++){
			k = num[i+start_index];
			num[i+start_index] = num[end_index-i];
			num[end_index-i] = k;
		}
	}
}
#endif

int netscan_addr_random(struct netscan_t *scan)
{
	unsigned int i = 0, idx = 0, tmp = 0;
	unsigned int addr_cnt = 0, *addr_out = NULL;
	
	if(!scan)
		return -1;
	
	if(test_bit(SCAN_FLAG_ADDR_CONTINUE, &scan->flags)){
		if(scan->addr)
			return -1;
		addr_cnt = scan->eaddr - scan->saddr + 1;
		addr_out = (unsigned int *)malloc(sizeof(unsigned int) * addr_cnt);
		if(!addr_out){
			return -1;
		}
		for(i=0; i<addr_cnt; i++){
			addr_out[i] = scan->saddr + i;
		}
		scan->addr = addr_out;
		scan->addr_num = addr_cnt;
		clear_bit(SCAN_FLAG_ADDR_CONTINUE, &scan->flags);
	}

	if(!scan->addr || !scan->addr_num)
		return -1;
	addr_cnt = scan->addr_num;
	srand_curtime();
	for(i=0; i<addr_cnt; i++){
		idx = rand_natural(addr_cnt);
		tmp = scan->addr[idx];
		scan->addr[idx] = scan->addr[i];
		scan->addr[i] = tmp;
	}
	
	set_bit(SCAN_FLAG_ADDR_DISCONTINUE, &scan->flags);
	return 0;
}

int netscan_port_random(struct netscan_t *scan)
{
	unsigned int i = 0, idx = 0;
	unsigned int port_cnt = 0;
	unsigned short j = 0, tmp = 0, *port_out = NULL;
	
	if(!scan)
		return -1;
	
	if(test_bit(SCAN_FLAG_PORT_CONTINUE, &scan->flags)){
		if(scan->port)
			return -1;
		port_cnt = (unsigned int)(scan->eport- scan->sport+ 1);
		port_out = (unsigned short *)malloc(sizeof(unsigned short) * port_cnt);
		if(!port_out){
			return -1;
		}
		for(j=0; j<port_cnt; j++){
			port_out[j] = scan->sport+ j;
		}
		scan->port = port_out;
		scan->port_num = port_cnt;
		clear_bit(SCAN_FLAG_PORT_CONTINUE, &scan->flags);
	}

	if(!scan->port || !scan->port_num)
		return -1;
	port_cnt = scan->port_num;
	srand_curtime();
	for(i=0; i<port_cnt; i++){
		idx = rand_natural(port_cnt);
		tmp = scan->port[idx];
		scan->port[idx] = scan->port[i];
		scan->port[i] = tmp;
	}

	set_bit(SCAN_FLAG_PORT_DISCONTINUE, &scan->flags);
	set_bit(SCAN_FLAG_RANDOM, &scan->flags);
	return 0;
}

int netscan_check(struct netscan_t *scan)
{
	if(test_bit(SCAN_FLAG_ADDR_CONTINUE, &scan->flags)){
		if(scan->saddr > scan->eaddr)
			return 0;
	}
	else if(test_bit(SCAN_FLAG_ADDR_DISCONTINUE, &scan->flags)){
		if(!scan->addr || !scan->addr_num)
			return 0;
	}
	else
		return 0;

	if(!test_bit(SCAN_FLAG_ASCEND, &scan->flags) && !test_bit(SCAN_FLAG_DESCEND, &scan->flags)
		&& !test_bit(SCAN_FLAG_RANDOM, &scan->flags) && !test_bit(SCAN_FLAG_NO_PORT, &scan->flags))
		set_bit(SCAN_FLAG_ASCEND, &scan->flags);

	if(test_bit(SCAN_FLAG_PORT_CONTINUE, &scan->flags)){
		if(scan->sport > scan->eport)
			return 0;
		if(test_bit(SCAN_FLAG_RANDOM, &scan->flags))
			netscan_port_random(scan);
	}
	else if(test_bit(SCAN_FLAG_PORT_DISCONTINUE, &scan->flags)){
		if(!scan->port || !scan->port_num)
			return 0;
		else{
			if(test_bit(SCAN_FLAG_RANDOM, &scan->flags))
				netscan_port_random(scan);
			else if(test_bit(SCAN_FLAG_ASCEND, &scan->flags)){
				bubble_sort_port(scan->port, 0, scan->port_num-1, 1);
			}
			else if(test_bit(SCAN_FLAG_DESCEND, &scan->flags)){
				bubble_sort_port(scan->port, 0, scan->port_num-1, 0);
			}
		}
	}
	else{
		set_bit(SCAN_FLAG_NO_PORT, &scan->flags);
	}

	netscan_t_print(scan);
	return 1;
}

/*
int netscan_split(struct netscan_t *scan, struct netscan_t *scan_ary, unsigned int ary_num)
{
	unsigned int addr_cnt, port_cnt, scan_cnt;
	unsigned int i_int, interval = 0, add = 0;
	unsigned short i_short;
	int idx = 0;
	
	if(!scan || !scan_ary || ary_num <= 1)
		return -1;
	if(!netscan_check(scan))
		return -1;

	if(test_bit(SCAN_FLAG_ADDR_CONTINUE, &scan->flags)){
		addr_cnt = scan->eaddr - scan->saddr + 1;
	}
	else{
		addr_cnt = scan->addr_num;
	}

	if(test_bit(SCAN_FLAG_PORT_CONTINUE, &scan->flags)){
		port_cnt = scan->eport - scan->sport + 1;
	}
	else{
		port_cnt = scan->port_num;
	}

	if(addr_cnt == 1){
		interval = port_cnt / ary_num;
		if(!interval)	interval = 1;
		add = port_cnt % ary_num;
		idx = 0;
		for(i_int=0; i_int<port_cnt; i_int += interval){
			scan_ary[idx].saddr = scan->saddr;
			scan_ary[idx].eaddr = scan->saddr;
			if(test_bit(SCAN_FLAG_ASCEND, &scan->flags)){
				scan_ary[idx].sport = scan->sport + (unsigned short)i_int;
			}
			else if(test_bit(SCAN_FLAG_DESCEND, &scan->flags)){
				scan_ary[idx].sport = scan->eport - (unsigned short)i_int;
			}
			else{
				scan_ary[idx].sport = scan->port[i_int];
			}
			++idx;
		}
	}

	if(addr_cnt <= ary_num){
		
	}
}
*/




int netscan_done(struct netscan_t *scan, void *arg, int (*proc)(unsigned int addr, unsigned short port, void *arg))
{
	unsigned int addr, i = 0, j = 0;
	unsigned short port = 0;
	int scan_flag = 0, no_port = 0;
	
	if(!scan)
		return -1;
	if(!netscan_check(scan)){
		return -1;
	}

	if(test_bit(SCAN_FLAG_NO_PORT, &scan->flags))
		no_port = 1;
	else{
		if(scan->port && scan->port_num)
			scan_flag = SCAN_FLAG_RANDOM;
		else if(test_bit(SCAN_FLAG_ASCEND, &scan->flags))
			scan_flag = SCAN_FLAG_ASCEND;
		else if(test_bit(SCAN_FLAG_DESCEND, &scan->flags))
			scan_flag = SCAN_FLAG_DESCEND;
		else
			return -1;
	}

	if(test_bit(SCAN_FLAG_ADDR_CONTINUE, &scan->flags)){
		for(addr=scan->saddr; addr<=scan->eaddr; addr++){
			if(no_port){
				proc(addr, 0, arg);
				continue;
			}
			
			if(scan_flag == SCAN_FLAG_ASCEND){
				for(port=scan->sport; port<=scan->eport; port++){
					proc(addr, port, arg);
				}
			}
			else if(scan_flag == SCAN_FLAG_DESCEND){
				for(port=scan->eport; port<=scan->sport; port++){
					proc(addr, port, arg);
				}
			}
			else{
				for(i=0; i<scan->port_num; i++){
					port = scan->port[i];
					proc(addr, port, arg);
				}
			}
		}
	}
	else{
		for(j=0; j<scan->addr_num; j++){
			addr = scan->addr[j];

			if(no_port){
				proc(addr, 0, arg);
				continue;
			}
			
			if(scan_flag == SCAN_FLAG_ASCEND){
				for(port=scan->sport; port<=scan->eport; port++){
					proc(addr, port, arg);
				}
			}
			else if(scan_flag == SCAN_FLAG_DESCEND){
				for(port=scan->eport; port<=scan->sport; port++){
					proc(addr, port, arg);
				}
			}
			else{
				for(i=0; i<scan->port_num; i++){
					port = scan->port[i];
					proc(addr, port, arg);
				}
			}
		}
	}
	
	return 0;
}

int netscan_get_targe_num(struct netscan_t *scan)
{
	int addr_count = 0, port_count = 0;

	if(!scan)
		return 0;
	
	if(scan->addr && scan->addr_num)
		addr_count = scan->addr_num;
	else
		addr_count = 1 + scan->eaddr - scan->saddr;

	if(scan->port && scan->port_num)
		port_count = scan->port_num;
	else
		port_count = 1 + scan->eport - scan->sport;

	if(port_count > 0)
		return port_count * addr_count;
	else
		return addr_count;
}

void netscan_t_print(struct netscan_t *scan)
{
	int i = 0;
	char ip_buf[16] = {0};

	printf("----------- netscan_t ----------\n");
	printf("ip=[ ");
	if(scan->addr && scan->addr_num){
		printf("%s", ip_htoa(scan->addr[0], ip_buf));
		for(i=1; i<scan->addr_num; i++){
			printf(", %s", ip_htoa(scan->addr[i], ip_buf));
		}
	}
	else{
		printf("%s-", ip_htoa(scan->saddr, ip_buf));
		printf("%s", ip_htoa(scan->eaddr, ip_buf));
	}
	printf(" ]\n");

	printf("port=[ ");
	if(scan->port && scan->port_num){
		printf("%u", scan->port[0]);
		for(i=1; i<scan->port_num; i++){
			printf(", %u", scan->port[i]);
		}
	}
	else{
		printf("%u-%u", scan->sport, scan->eport);
	}
	printf(" ]\n");

	if(test_bit(SCAN_FLAG_ASCEND, &scan->flags))
		printf("seq=ascend\n");
	else if(test_bit(SCAN_FLAG_DESCEND, &scan->flags))
		printf("seq=descend\n");
	else if(test_bit(SCAN_FLAG_RANDOM, &scan->flags))
		printf("seq=random\n");

	printf("-------------------------------\n");
}






int netscan_result_init(struct netscan_result *result, int type)
{
	if(!result)
		return -1;
	if(type != 0 && type != 1)
		return -1;
	if (pthread_mutex_init(&(result->list_lock), NULL)){
		return -1;
	}
	result->type = type;
	result->num = 0;
	INIT_SLIST_HEAD(&result->addr_port_list);
	return 0;
}

int netscan_result_destory(struct netscan_result *result, int free_self)
{
	struct addr_port *pos = NULL;
	if(!result)
		return -1;
	
	pthread_mutex_destroy(&(result->list_lock)); 
	if(!slist_empty(&result->addr_port_list)){
		slist_while_get_head_entry(pos, &result->addr_port_list, slist)
			free(pos);
	}
	result->num = 0;
	if(free_self)
		free(result);
	return 0;
}

int save_addr_port(struct netscan_result *result, unsigned int addr, unsigned short port)
{
	struct addr_port *save = NULL;

	save = (struct addr_port *)malloc(sizeof(struct addr_port));
	if(!save)
		return -1;
	save->addr = addr;
	save->port = port;
	INIT_SLIST_NODE(&save->slist);
	pthread_mutex_lock(&(result->list_lock));
	slist_add(&result->addr_port_list, &save->slist);
	++result->num;
	pthread_mutex_unlock(&(result->list_lock));
	return 0;
}

char *ttl_2_os_type(unsigned char ttl, char *os_type, unsigned int size)
{
// maybe unreliable
	if(ttl <= 32)
		strncpy(os_type, "Windows 95/98/Me", size);
	else if(ttl <= 64)
		strncpy(os_type, "Linux", size);
	else if(ttl <= 128)
		strncpy(os_type, "Windows NT/2000/XP/2003/Vista", size);
	else
		strncpy(os_type, "Unix", size);
	return os_type;
}




struct arg_ipport_t
{
	struct slist_node slist;
	unsigned int sdata;
	unsigned int edata;
	int is_section;
};

static int str_to_iport(char *str, unsigned int *out, int is_ip)
{
	if(is_ip){
		if(!ip_atoh(str, out))
			return -1;
	}
	else{
		if(sscanf(str, "%u", out) < 1)
			return -1;
		if(*out >= 65535)
			return -1;
	}
	return 0;
}

int netscan_ipport_arglist_count(struct slist_head *arg_list)
{
	struct arg_ipport_t *pos = NULL;
	int count = 0;

	if(slist_empty(arg_list))
		return 0;

	slist_for_each_entry(pos, arg_list, slist){
		if(pos->is_section)
			count += 1 + pos->edata - pos->sdata;
		else
			++count;
	}
	return count;
}

int __netscan_parse_arg_ipport(char *arg_str, struct slist_head *arg_list, int is_ip)
{
	int is_section = 0;
	char *arg_e = strchr(arg_str, '-');
	unsigned int s = 0, e = 0;
	struct arg_ipport_t *arg_t = NULL;

	if(arg_e){
		++arg_e;
		if(str_to_iport(arg_e, &e, is_ip) < 0)
			return 1;
		is_section = 1;
	}

	if(str_to_iport(arg_str, &s, is_ip) < 0)
		return -1;

	arg_t = (struct arg_ipport_t *)malloc(sizeof(struct arg_ipport_t));
	if(!arg_t)
		return -1;
	memset(arg_t, 0, sizeof(struct arg_ipport_t));
	arg_t->sdata = s;
	if(is_section && e != s){
		if(e < s){
			arg_t->sdata = e;
			arg_t->edata = s;
		}
		else
			arg_t->edata = e;
		arg_t->is_section = 1;
	}

	slist_add_head(arg_list, &(arg_t->slist));

	return 0;
}

int netscan_parse_arg_ipport(char *arg_str, struct slist_head *arg_list, int is_ip)
{
	char *p = arg_str;
	char *start = NULL;

	while(*p != '\0'){
		if((*p >= '0' && *p <= '9') || *p == '-' || (is_ip && *p == '.')){
			if(!start)
				start = p;
		}
		else{
			if(start){
				*p = '\0';
				__netscan_parse_arg_ipport(start, arg_list, is_ip);
				start = NULL;
			}
		}
		++p;
	}
	if(start)
		__netscan_parse_arg_ipport(start, arg_list, is_ip);

	return 0;
}

int netscan_parse_arg_ipport_file(char *arg_file, struct slist_head *arg_list, int is_ip)
{
	FILE *fp = NULL;
	char buf[2048] = {0};

	fp = fopen(arg_file, "r");
	if(!fp)
		return -1;

	while(fgets(buf,sizeof(buf),fp)){
		if(buf[0] != '#')
			netscan_parse_arg_ipport(buf, arg_list, is_ip);
		memset(buf, 0, sizeof(buf));
	}

	fclose(fp);
	return 0;
}

int netscan_arg_ip_to_netscan_t(struct slist_head *arg_list, struct netscan_t *scan)
{
	struct arg_ipport_t *arg_t = NULL;
	int count = 0, index = -1;
	unsigned int data = 0;
	
	if(slist_empty(arg_list))
		return 0;
	if(arg_list->head == arg_list->tail){
		arg_t = slist_head_entry(arg_list, struct arg_ipport_t, slist);
		if(!arg_t->is_section)
			arg_t->edata = arg_t->sdata;
		scan->saddr = arg_t->sdata;
		scan->eaddr = arg_t->edata;
		set_bit(SCAN_FLAG_ADDR_CONTINUE, &scan->flags);
	}
	else{
		count = netscan_ipport_arglist_count(arg_list);
		scan->addr = (unsigned int *)malloc(sizeof(unsigned int) * count);
		if(!scan->addr)
			return -1;
		scan->addr_num = count;
		set_bit(SCAN_FLAG_ADDR_DISCONTINUE, &scan->flags);

		slist_for_each_entry(arg_t, arg_list, slist){
			if(arg_t->is_section){
				for(data=arg_t->sdata; data<=arg_t->edata; data++)
					scan->addr[++index] = data;
			}
			else
				scan->addr[++index] = arg_t->sdata;
		}
	}

	return 0;
}

int netscan_arg_port_to_netscan_t(struct slist_head *arg_list, struct netscan_t *scan)
{
	struct arg_ipport_t *arg_t = NULL;
	int count = 0, index = -1;
	unsigned int data = 0;
	
	if(slist_empty(arg_list))
		return 0;
	if(arg_list->head == arg_list->tail){
		arg_t = slist_head_entry(arg_list, struct arg_ipport_t, slist);
		if(!arg_t->is_section)
			arg_t->edata = arg_t->sdata;
		scan->sport = (unsigned short)arg_t->sdata;
		scan->eport = (unsigned short)arg_t->edata;
		set_bit(SCAN_FLAG_PORT_CONTINUE, &scan->flags);
	}
	else{
		count = netscan_ipport_arglist_count(arg_list);
		scan->port = (unsigned short *)malloc(sizeof(unsigned short) * count);
		if(!scan->port)
			return -1;
		scan->port_num = count;
		set_bit(SCAN_FLAG_PORT_DISCONTINUE, &scan->flags);
		
		slist_for_each_entry(arg_t, arg_list, slist){
			if(arg_t->is_section){
				for(data=arg_t->sdata; data<=arg_t->edata; data++)
					scan->port[++index] = (unsigned short)data;
			}
			else
				scan->port[++index] = (unsigned short)arg_t->sdata;
		}
	}

	return 0;
}

enum NETSCAN_ARG_TYPE{
	NETSCAN_ARG_IP = ARG_VALUE_TYPE_OTHER,
	NETSCAN_ARG_IP_FILE,
	NETSCAN_ARG_PORT,
	NETSCAN_ARG_PORT_FILE,
};

int netscan_arg_deal(char *arg_key, char *arg_value, int value_type, void *value)
{
	struct netscan_t *p_netscan = (struct netscan_t *)value;
	struct slist_head arg_list;

	INIT_SLIST_HEAD(&arg_list);
	switch(value_type){
	case NETSCAN_ARG_IP:
		netscan_parse_arg_ipport(arg_value, &arg_list, 1);
		netscan_arg_ip_to_netscan_t(&arg_list, p_netscan);
		break;
	case NETSCAN_ARG_IP_FILE:
		netscan_parse_arg_ipport_file(arg_value, &arg_list, 1);
		netscan_arg_ip_to_netscan_t(&arg_list, p_netscan);
		break;
	case NETSCAN_ARG_PORT:
		netscan_parse_arg_ipport(arg_value, &arg_list, 0);
		netscan_arg_port_to_netscan_t(&arg_list, p_netscan);
		break;
	case NETSCAN_ARG_PORT_FILE:
		netscan_parse_arg_ipport_file(arg_value, &arg_list, 0);
		netscan_arg_port_to_netscan_t(&arg_list, p_netscan);
		break;
	default:
		break;
	}

	return 0;
}
int netscan_seq_arg_deal(char *arg_key, char *arg_value, int value_type, void *value)
{
	struct netscan_t *p_netscan = (struct netscan_t *)value;
	
	if(!strcmp(arg_value, "ascend")){
		set_bit(SCAN_FLAG_ASCEND, &p_netscan->flags);
	}
	else if(!strcmp(arg_value, "descend")){
		set_bit(SCAN_FLAG_DESCEND, &p_netscan->flags);
	}
	else if(!strcmp(arg_value, "random")){
		set_bit(SCAN_FLAG_RANDOM, &p_netscan->flags);
	}

	return 0;	
}

struct netscan_t netscan_common;
struct arg_parse_t netscan_arg[] = {
	{"-ip", &netscan_common, 0, 1, netscan_arg_deal, NETSCAN_ARG_IP, 0, NULL},
	{"-ip-file", &netscan_common, 0, 1, netscan_arg_deal, NETSCAN_ARG_IP_FILE, 0, NULL},
	{"-port", &netscan_common, 0, 1, netscan_arg_deal, NETSCAN_ARG_PORT, 0, NULL},
	{"-port-file", &netscan_common, 0, 1, netscan_arg_deal, NETSCAN_ARG_PORT_FILE, 0, NULL},
	{"-seq", &netscan_common, 0, 1, netscan_seq_arg_deal, 0, 0, NULL},
	{NULL, NULL, 0, 0, NULL, 0, 0, NULL}
};

int netscan_arg_parse(int argc, char **argv, int *new_argc, char **new_argv, struct netscan_t *scan)
{
	int ret = 0;
	ret = arg_parse(argc, argv, netscan_arg, new_argc, new_argv);
	memcpy(scan, &netscan_common, sizeof(struct netscan_t));
	return ret;
}



extern void tcpscan_usage();
extern int tcpscan_main(int argc, char **argv);

extern void udpscan_usage();
extern int udpscan_main(int argc, char **argv);

extern void icmpscan_usage();
extern int icmpscan_main(int argc, char **argv);

extern void ssdpscan_usage();
extern int ssdpscan_main(int argc, char **argv);

struct child_cmd_t netscan_cmd_list[] = {
	{"tcpscan", NULL, tcpscan_usage, tcpscan_main},
	{"udpscan", NULL, udpscan_usage, udpscan_main},
	{"icmpscan", NULL, icmpscan_usage, icmpscan_main},
	{"ssdpscan", NULL, ssdpscan_usage, ssdpscan_main},
};

int main(int argc, char **argv)
{
	wf_child_cmd_mini(netscan_cmd_list, "netscan");
	return 0;
}

