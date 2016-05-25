#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "libwf.h"

static int readServerIPList(char *filename, char ipdest[][16], int ip_num_max)
{
	char ipb[64]= {0};
	int line=0,len=0;
	char *pstr=NULL;
	FILE *fp=NULL;

	if((fp = fopen(filename,"a+"))==NULL){
		return -1;
	}
	while(fgets(ipb,sizeof(ipb)-1,fp)!=NULL)
	{
		if(line >= ip_num_max){
			break;
		}
		if(ipb[0] == '#')
			continue;
		pstr = ipb;
		len=0;
		while(*pstr!='\n'){
			len++;
			pstr++;
		}
		strncpy(ipdest[line],ipb,len);
		line++;
	}
	fclose(fp);
	return line;
}

static int writefile(char *filename,char *wbuf)
{
	FILE *fp=NULL;

	if((fp = fopen(filename,"w+"))==NULL)
	{
		return -1;
	}
	if(!wbuf)
	{
		return -1;
	}
	fputs(wbuf,fp);
	fclose(fp);
}

void print_ip_list(char **ip_list, int ip_num)
{
	int i=0;

	for(; i<ip_num; i++){
		printf("%s\n", ip_list[i]);
	}
}
void print_ip_list2(char ip_list[][16], int ip_num)
{
	int i=0;

	for(; i<ip_num; i++){
		printf("%s\n", ip_list[i]);
	}
}

char ip_list[100][16];
int main(int argc, char **argv)
{
	unsigned long tm1, tm2;
	int ret = 0, ip_num = 0;
	char best_ip[16] = "0.0.0.0";

	ip_num = readServerIPList(argv[1], ip_list, 40);
	if(ip_num <= 0){
		printf("no ip list\n");
		exit(1);
	}

	get_system_uptime(&tm1);
	ret = icmp_select_best_ip(ip_list, ip_num, best_ip);
	get_system_uptime(&tm2);
	printf("best_ip: %s\n", best_ip);
	printf("%lu s \n", tm2 - tm1);

	return 0;
}

