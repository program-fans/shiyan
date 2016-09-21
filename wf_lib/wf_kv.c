#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "linux_list.h"
#include "wf_kv.h"

struct wf_kv_t
{
	struct list_head list;
	int kv_index:8;
	void *key;
	unsigned int key_size;
	void *value;
	unsigned int value_size;
};

#define KV_TABLE_LIST_NUM		255
struct wf_kv_table
{
	unsigned int init;
	unsigned int count;
	struct list_head kv_head[KV_TABLE_LIST_NUM];
};

static struct wf_kv_table kv_table;

static void kv_table_init_check(struct wf_kv_table *t)
{
	int i=0;
	if( !t || t->init )	return;
	t->count = 0;
	for(i=0; i<KV_TABLE_LIST_NUM; i++)
		INIT_LIST_HEAD(&(t->kv_head[i]));
	t->init = 1;
}

static void kv_free(struct wf_kv_t *kv)
{
	if( !kv )	return;
	if(kv->key)	free(kv->key);
	if(kv->value)	free(kv->value);
	//if( !list_empty_careful(&(kv->list)) )
	free(kv);
}

static void kv_table_destory(struct wf_kv_table *t)
{
	int i=0;
	struct wf_kv_t *pos, *n;
	
	if(!t || !t->init)
		return;
	for(i=0; i<KV_TABLE_LIST_NUM; i++)
	{
		if(list_empty_careful(&(t->kv_head[i])))
			continue;
		list_for_each_entry_safe(pos, n, &(t->kv_head[i]), list){
			//list_del_init(&(pos->list));
			kv_free(pos);
		}
	}
	t->init = 0;
	kv_table_init_check(t);
}

static int get_kv_index(void *key, unsigned int size)
{
	int  i=0;
	unsigned int m=0;
	unsigned char *ptr = (unsigned char *)key;

	for(i=0; i<size; i++)
	{
		m += (unsigned int)(*ptr++);
	}

	return (int)(m / size);
}

static struct wf_kv_t *kv_create(int kv_index, void *key, unsigned int key_size, void *value, unsigned int value_size)
{
	struct wf_kv_t *kv=NULL;
	
	kv = (struct wf_kv_t *)malloc(sizeof(struct wf_kv_t));
	if(!kv)	return NULL;
	memset(kv, 0, sizeof(struct wf_kv_t));
	kv->key = malloc(key_size);
	if(!kv->key)	goto FREE_KV;
	kv->value = malloc(value_size);
	if(!kv->value)	goto FREE_KV;

	memcpy(kv->key, key, key_size);
	memcpy(kv->value, value, value_size);
	kv->key_size = key_size;
	kv->value_size = value_size;
	kv->kv_index = kv_index;
	INIT_LIST_HEAD( &(kv->list) );
	
	return kv;

FREE_KV:
	kv_free(kv);
	return NULL;
}

static struct wf_kv_t *find_kv(int kv_index, void *key, unsigned int key_size)
{
	struct wf_kv_t *kv=NULL;
	if( list_empty(&(kv_table.kv_head[kv_index])) )	return NULL;
	list_for_each_entry(kv, &(kv_table.kv_head[kv_index]), list)
	{
		if( kv->key_size != key_size)	continue;
		if( memcmp(kv->key, key, kv->key_size) )	continue;
		return kv;
	}
	return NULL;
}

static void put_kv(int kv_index, struct wf_kv_t *kv)
{
	if(!kv)	return;
	list_add_tail(&(kv->list), &(kv_table.kv_head[kv_index]));
	++kv_table.count;
}
static void remove_kv(struct wf_kv_t *kv)
{
	if(!kv)	return;
	list_del_init(&(kv->list));
	--kv_table.count;
}
static int replace_kv(struct wf_kv_t *kv, void *value, unsigned int value_size)
{
	void *ptr=NULL;
	if(!kv)	return -1;

	ptr = malloc(value_size);
	if(!ptr)	return -1;
	memcpy(ptr, value, value_size);
	if( kv->value )	free(kv->value);
	kv->value = ptr;
	return 0;
}
static int key_check(void *key, unsigned int key_size)
{
	if(key == NULL)	return 0;
	if(key_size > 1024 || key_size == 0)	return 0;
	return 1;
}
/*
static int value_check(void *value, unsigned int value_size)
{
	if(value == NULL)		return 0;
	if(value_size == 0)	return 0;
	return 1;
}
*/
static int wf_kv_param_check(void *key, unsigned int key_size, void *value, unsigned int value_size)
{
	if(key == NULL)	return 0;
	if(key_size > 1024 || key_size == 0)	return 0;
	if(value == NULL)		return 0;
	if(value_size == 0)	return 0;
	return 1;
}

int wf_put_kv(void *key, unsigned int key_size, void *value, unsigned int value_size)
{
	struct wf_kv_t *kv=NULL;
	int kv_index = 0;

	if( !wf_kv_param_check(key, key_size, value, value_size) )	return -1;
	kv_table_init_check(&kv_table);
	
	kv_index = get_kv_index(key, key_size);
	if( find_kv(kv_index, key, key_size) )	return -1;
	kv = kv_create(kv_index, key, key_size, value, value_size);
	if(!kv)	return -1;

	put_kv(kv_index, kv);

	return 0;
}

int wf_get_kv(void *key, unsigned int key_size, void *value, unsigned int value_size)
{
	int kv_index = 0;
	struct wf_kv_t *kv=NULL;
	
	if( !wf_kv_param_check(key, key_size, value, value_size) )	return -1;
	kv_table_init_check(&kv_table);

	kv_index = get_kv_index(key, key_size);

	kv = find_kv(kv_index, key, key_size);
	if(!kv)	return 0;

	if( kv->value_size > value_size)		return -1;
	memcpy(value, kv->value, kv->value_size);
	return kv->value_size;
}

unsigned int wf_get_kv_count()
{
	return kv_table.count;
}

int wf_replace_kv(void *key, unsigned int key_size, void *value, unsigned int value_size)
{
	int kv_index = 0;
	struct wf_kv_t *kv=NULL;
	
	if( !wf_kv_param_check(key, key_size, value, value_size) )	return -1;
	kv_table_init_check(&kv_table);

	kv_index = get_kv_index(key, key_size);

	kv = find_kv(kv_index, key, key_size);
	if(!kv)	return -1;

	return replace_kv(kv, value, value_size);
}

int wf_del_kv(void *key, unsigned int key_size)
{
	int kv_index = 0;
	struct wf_kv_t *kv=NULL;
	
	if( !key_check(key, key_size) )	return -1;
	kv_table_init_check(&kv_table);

	kv_index = get_kv_index(key, key_size);

	kv = find_kv(kv_index, key, key_size);
	if(!kv)	return 0;

	remove_kv(kv);
	kv_free(kv);
	return 0;
}

void wf_kv_table_destory()
{
	kv_table_destory(&kv_table);
}

#if 0
int main()
{
	int ret=0;
	char buf[1024];

	ret=wf_string_put_kv("wolf", "wolf-lone");
	ret=wf_string_put_kv("dog", "dog-dan");

	memset(buf, 0, 1024);
	ret=wf_string_get_kv("wolf", buf, 1024);
	printf("buf: %s \t ret=%d \n", buf, ret);
	memset(buf, 0, 1024);
	ret=wf_string_get_kv("dog", buf, 1024);
	printf("buf: %s \t ret=%d \n", buf, ret);
	
	ret=wf_string_replace_kv("wolf", "wolf-dog");
	memset(buf, 0, 1024);
	ret=wf_string_get_kv("wolf", buf, 1024);
	printf("buf: %s \t ret=%d \n", buf, ret);

	ret=wf_string_del_kv("dog");
	memset(buf, 0, 1024);
	ret=wf_string_get_kv("dog", buf, 1024);
	printf("buf: %s \t ret=%d \n", buf, ret);

	return 0;
}
#endif

