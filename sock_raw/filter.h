#ifndef FILTER_H_
#define FILTER_H_

#define SELECT_STR_EQUAL			"="
#define SELECT_STR_NOT_EQUAL		"!="

enum FILTER_SELECT
{
	FILTER_SELECT_EQUAL,					// =
	FILTER_SELECT_NOT_EQUAL				// !=
};

enum PROTO_FLAG
{
	PROTO_FLAG_LEVEL_3=3,					// mac 层
	PROTO_FLAG_LEVEL_4=4,					// ip 层
	PROTO_FLAG_LEVEL_5=5					// 应用层
};
struct filter_proto
{
	enum PROTO_FLAG flag;
	unsigned int proto;
	enum FILTER_SELECT select;
};

#define DIRECTING_SRC_STR			"src"
#define DIRECTING_DST_STR			"dst"

enum DIRECTION_FLAG
{
	DIRECTION_FLAG_NO,					// 源或目的
	DIRECTION_FLAG_SRC,					// 源
	DIRECTION_FLAG_DST					// 目的
};

struct filter_mac
{
	enum DIRECTION_FLAG flag;
	unsigned char mac[6];
	enum FILTER_SELECT select;
};

struct filter_ip
{
	enum DIRECTION_FLAG flag;
	char ip_s[16];
	unsigned int ip_addr;
	struct in_addr addr;
	enum FILTER_SELECT select;
};

struct filter_port
{
	enum DIRECTION_FLAG flag;
	unsigned short port;
	unsigned short port_net;
	enum FILTER_SELECT select;
};
/*
enum FILTER_RULE_MASK
{
	FILTER_RULE_MASK_PROTO=1,
	FILTER_RULE_MASK_MAC,
	FILTER_RULE_MASK_IP,
	FILTER_RULE_MASK_PORT
};
*/
#define RULE_STR_PROTO				"proto"
#define RULE_STR_IP					"ip"
#define RULE_STR_PORT				"port"
#define RULE_STR_MAC				"mac"

#define FILTER_RULE_NUM_MAX	10

struct filter_rule
{
	int enable;
	//unsigned long rule_mask;
	struct filter_proto *proto[FILTER_RULE_NUM_MAX];
	int proto_num;
	struct filter_ip *ip[FILTER_RULE_NUM_MAX];
	int ip_num;
	struct filter_port *port[FILTER_RULE_NUM_MAX];
	int port_num;
	struct filter_mac *mac[FILTER_RULE_NUM_MAX];
	int mac_num;
};

#define match_tag(str, tag)	(!strncmp(str, tag, strlen(tag)))

void rule_init();

void rule_close();

void rule_enable();

void rule_disEnable();

int rule_str_parse(char *str);

void print_rule();

#define FILTER_ACCEPT	0
#define FILTER_DROP		1

int filter(unsigned char *buf, int len);

#endif
