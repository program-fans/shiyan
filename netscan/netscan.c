#include <stdio.h>
#include <stdlib.h>

#include "netscan.h"

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

	if(test_bit(SCAN_FLAG_PORT_CONTINUE, &scan->flags)){
		if(scan->sport > scan->eport)
			return 0;
	}
	else if(test_bit(SCAN_FLAG_PORT_DISCONTINUE, &scan->flags)){
		if(!scan->port || !scan->port_num)
			return 0;
	}
	else{
		set_bit(SCAN_FLAG_NO_PORT, &scan->flags);
		return 1;
	}

	if(test_bit(SCAN_FLAG_ASCEND, &scan->flags) || test_bit(SCAN_FLAG_DESCEND, &scan->flags)){
		if(test_bit(SCAN_FLAG_PORT_DISCONTINUE, &scan->flags))
			return 0;
	}
	else if(test_bit(SCAN_FLAG_RANDOM, &scan->flags)){
		if(test_bit(SCAN_FLAG_PORT_CONTINUE, &scan->flags))
			return 0;
	}
	else{
		if(!test_bit(SCAN_FLAG_NO_PORT, &scan->flags))
			return 0;
	}
	
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
		srand_curtime();
		for(i=0; i<addr_cnt; i++){
			addr_out[i] = scan->saddr + i;
		}
		scan->addr = addr_out;
		scan->addr_num = addr_cnt;
		clear_bit(SCAN_FLAG_ADDR_CONTINUE, &scan->flags);
	}
	else{
		if(!scan->addr || !scan->addr_num)
			return -1;
		addr_cnt = scan->addr_num;
		for(i=0; i<addr_cnt; i++){
			idx = rand_natural(addr_cnt);
			tmp = scan->addr[idx];
			scan->addr[idx] = scan->addr[i];
			scan->addr[i] = tmp;
		}
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
		srand_curtime();
		for(j=0; j<port_cnt; j++){
			port_out[j] = scan->sport+ j;
		}
		scan->port = port_out;
		scan->port_num = port_cnt;
		clear_bit(SCAN_FLAG_PORT_CONTINUE, &scan->flags);
	}
	else{
		if(!scan->port || !scan->port_num)
			return -1;
		port_cnt = scan->port_num;
		for(i=0; i<port_cnt; i++){
			idx = rand_natural(port_cnt);
			tmp = scan->port[idx];
			scan->port[idx] = scan->port[i];
			scan->port[i] = tmp;
		}
	}

	set_bit(SCAN_FLAG_PORT_DISCONTINUE, &scan->flags);
	set_bit(SCAN_FLAG_RANDOM, &scan->flags);
	return 0;
}

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
	
	if(test_bit(SCAN_FLAG_ASCEND, &scan->flags))
		scan_flag = SCAN_FLAG_ASCEND;
	else if(test_bit(SCAN_FLAG_DESCEND, &scan->flags))
		scan_flag = SCAN_FLAG_DESCEND;
	else
		scan_flag = SCAN_FLAG_RANDOM;

	if(test_bit(SCAN_FLAG_NO_PORT, &scan->flags))
		no_port = 1;

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

