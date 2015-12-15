#ifndef WF_PARAM_H_
#define WF_PARAM_H_

#include "linux_list.h"

#ifdef  __cplusplus
extern "C" {
#endif

typedef enum
{
	PARAM_STRING,
	PARAM_RAW,
	PARAM_INT,
	PARAM_ARRAY_INT,
	PARAM_LONG,
	PARAM_LONG_LONG,
	PARAM_SHORT,
	PARAM_CHAR,
	PARAM_STRUCT_IN_ADDR,
}TXT_TYPE;

typedef struct
{
	char name[100];
	unsigned int   len;
	unsigned long 	 offset;
	char   type;
}txt_type;

struct txt_list
{
	struct list_head list;
	int find;
	txt_type txt;
};

struct txt_list_head
{
	struct list_head list;
	struct list_head member;
	struct list_head array;/*member contain array */
	char *init_addr; /*  first array addr */
	char *init_addr2; /*  used by child array when load para ,think about this situation when array contain a child_array */
	//int (*load_check)(struct txt_list_head*, void *data);
	int (*save_check)(struct txt_list_head*, unsigned long data);  /* if exist, != 0, ignore */
	int (*locate)(struct txt_list_head*, void* data, unsigned long index); /*  use to locate where to space*/
	int (*move)(struct txt_list_head*, void* data); /*  used to move entry to another space */
	void (*para_reinit)(void);
	int version; /* modify by zmb, 2011-01-15-17:39 to support version match*/
	int offset;/* used by child_array */
	int mx_nr;
	int size; /*  entry size */
	char title[100];
};

extern void txt_head_set_version(struct txt_list_head *txt, int version);
extern struct list_head *  txt_add(struct list_head *txt_head,char *name,unsigned int len,char type,unsigned long offset) ;
extern struct txt_list_head *txt_head_add(struct list_head *head, void *addr, char *title, int mx_nr, int size);
extern int wf_generic_load_param(char *name, struct list_head *head, void (*restore)(void));
extern int wf_generic_save_param(char *name, struct list_head *head);
extern void  free_txt_list_head(struct list_head *head);


#ifdef  __cplusplus
}
#endif

#endif
