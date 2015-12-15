#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "linux_list.h"
#include "wf_memory.h"

#if 0
#define BP_DEBUG()	printf(">>>>>>>>>> %s  %d  \n", __FUNCTION__, __LINE__);
#define malloc_print(ptr, size)		printf("start: %p  end: %p  size: %u \n", ptr, (char *)(ptr)+size, size);
#else
#define BP_DEBUG()
#define malloc_print(ptr, size)
#endif

struct mem_t
{
	struct list_head free_head;
	struct list_head use_head;
	unsigned int mem_size;
	void *mem;
};

struct mem_pool
{
	unsigned int enable;
	enum MemPoolMod mem_pool_mod;
	unsigned int all_memory;
	unsigned int pool_size;
	unsigned int mem_size;
	unsigned int mem_num;
	unsigned int free_pool_size;
	unsigned int use_pool_size;
	unsigned int free_mem_num;
	unsigned int use_mem_num;
	struct list_head free_mem_head;
	struct list_head use_mem_head;
	struct list_head pool_head;
};

static void free_mem(struct mem_t *mem)
{
	if(!mem)
		return;
	if(mem->mem)
		free(mem->mem);
	if( !list_empty_careful(&mem->free_head) )
		list_del(&mem->free_head);
	if( !list_empty_careful(&mem->use_head) )
		list_del(&mem->use_head);
	free(mem);
}
static unsigned int init_mem(struct mem_t *mem, unsigned int mem_size)
{
	if(!mem)
		return 0;
	INIT_LIST_HEAD(&mem->free_head);
	INIT_LIST_HEAD(&mem->use_head);
	mem->mem = malloc(mem_size);
	malloc_print(mem->mem, mem_size);
	if(mem->mem)
		mem->mem_size = mem_size;
	else
		mem->mem_size = 0;

	return mem->mem_size;
}

static void free_mem_list(struct list_head *list)
{
	struct mem_t *pos=NULL, *n=NULL;
	if(!list)
		return;

	if( !list_empty_careful(list) )
	{
		list_for_each_entry_safe(pos, n, list, free_head)
		{
			free_mem(pos);
		}
	}
}

static void free_use_mem_list(struct list_head *list)
{
	struct mem_t *pos=NULL, *n=NULL;
	if(!list)
		return;

	if( !list_empty_careful(list) )
	{
		list_for_each_entry_safe(pos, n, list, use_head)
		{
			free_mem(pos);
		}
	}
}

static void print_mem_pool(MemPool *pool)
{
	char mod_str[3][24]={"Mod_MemId_OutSet", "Mod_MemId_InSet", "Mod_NO_MemId"};
	
	printf("------ mem pool ------\n");
	printf("MemPoolMod: %s \n", mod_str[pool->mem_pool_mod]);
	printf("all_memory: %u \n", pool->all_memory);
	printf("pool_size: %u \n", pool->pool_size);
	printf("mem_num: %u \n", pool->mem_num);
	printf("mem_size: %u \n", pool->mem_size);
	
	printf("free_pool_size: %u \n", pool->free_pool_size);
	printf("use_pool_size: %u \n", pool->use_pool_size);
	printf("free_mem_num: %u \n", pool->free_mem_num);
	printf("use_mem_num: %u \n", pool->use_mem_num);
	printf("free_mem_list: %s \n", list_empty_careful(&pool->free_mem_head) ? "empty" : "not empty");
	printf("use_mem_list: %s \n", list_empty_careful(&pool->use_mem_head) ? "empty" : "not empty");
	printf("-------------------------\n");
}

void free_mem_pool(MemPool *pool)
{
	if(!pool)
		return;

	free_mem_list(&pool->free_mem_head);
	free_use_mem_list(&pool->use_mem_head);

	pool->all_memory = 0;
	pool->mem_num = 0;
	pool->mem_size = 0;
	pool->pool_size = 0;
	pool->free_mem_num = 0;
	pool->free_pool_size = 0;
	pool->use_mem_num = 0;
	pool->use_pool_size = 0;
	INIT_LIST_HEAD(&pool->free_mem_head);
	INIT_LIST_HEAD(&pool->use_mem_head);

	free(pool);
}

MemPool *new_mem_pool(unsigned int mem_num, unsigned int mem_size, enum MemPoolMod mod)
{
	MemPool *pool = NULL;
	struct mem_t *mem = NULL;
	unsigned short num, size, n;
	unsigned int i=0;
	MemId *mem_id;

	if(mem_num >= 0x0000FFFF || mem_size >= 0x0000FFFF)
		return NULL;
	if(mod == Mod_MemId_InSet && mem_size <= sizeof(MemId))
		return NULL;
	num = (unsigned short)mem_num;
	size = (unsigned short)mem_size;
	n = (unsigned short)sizeof(struct mem_t);
	
	pool = (MemPool *)malloc(sizeof(MemPool));
	if(pool == NULL)
		return NULL;
	malloc_print(pool, sizeof(MemPool));
	pool->mem_pool_mod = mod;
	pool->mem_num = mem_num;
	pool->mem_size = mem_size;
	pool->pool_size = num * size;
	pool->all_memory = pool->pool_size + (num * n) + sizeof(MemPool);
	pool->free_mem_num = pool->mem_num;
	pool->free_pool_size = pool->pool_size;
	pool->use_mem_num = 0;
	pool->use_pool_size = 0;
	INIT_LIST_HEAD(&pool->free_mem_head);
	INIT_LIST_HEAD(&pool->use_mem_head);
	INIT_LIST_HEAD(&pool->pool_head);

	for(i=0; i<pool->mem_num; i++)
	{
		mem = (struct mem_t *)malloc(sizeof(struct mem_t));
		malloc_print(mem, sizeof(struct mem_t));
		if(mem == NULL)
			goto MALLOC_ERR;
		if( init_mem(mem, pool->mem_size) == 0 )
			goto MALLOC_ERR;
		if(pool->mem_pool_mod == Mod_MemId_InSet)
		{
			mem_id = (MemId *)mem->mem;
			*mem_id = (MemId)&mem->mem;
		}
		list_add(&mem->free_head, &pool->free_mem_head);
	}

	Enable_MemPool(pool);
	return pool;

MALLOC_ERR:
	free_mem(mem);
	free_mem_pool(pool);
	return NULL;
}

MemPool *extend_mem_pool(MemPool *pool, unsigned int mem_num)
{
	struct mem_t *mem = NULL;
	unsigned short num, size, n;
	unsigned int i=0, new_size=0;
	struct list_head new_free_list;
	MemId *mem_id;

	if(mem_num >= 0x0000FFFF || !pool)
		return NULL;
	INIT_LIST_HEAD(&new_free_list);
	num = (unsigned short)mem_num;
	size = (unsigned short)pool->mem_size;
	n = (unsigned short)sizeof(struct mem_t);
	new_size = num * size;
	
	for(i=0; i<mem_num; i++)
	{
		mem = (struct mem_t *)malloc(sizeof(struct mem_t));
		malloc_print(mem, sizeof(struct mem_t));
		if(mem == NULL)
			goto MALLOC_ERR;
		if( init_mem(mem, pool->mem_size) == 0 )
			goto MALLOC_ERR;
		if(pool->mem_pool_mod == Mod_MemId_InSet)
		{
			mem_id = (MemId *)mem->mem;
			*mem_id = (MemId)&mem->mem;
		}
		list_add(&mem->free_head, &new_free_list);
	}

	list_splice_init(&new_free_list, &pool->free_mem_head);

	pool->mem_num += mem_num;
	pool->pool_size += new_size;
	pool->all_memory += new_size + (num * n);
	pool->free_mem_num = pool->mem_num;
	pool->free_pool_size = pool->pool_size;

	return pool;

MALLOC_ERR:
	free_mem(mem);
	free_mem_list(&new_free_list);
	return NULL;
}

void *borrow_mem(MemPool *pool, MemId *mem_id)
{
	struct mem_t *mem = NULL;
	void *ptr;
	
	if(!pool || !pool->enable || pool->free_mem_num == 0)
		return NULL;
	if(pool->mem_pool_mod == Mod_MemId_OutSet && !mem_id)
		return NULL;
	if( list_empty_careful(&pool->free_mem_head) )
		return NULL;
	
	mem = list_entry(pool->free_mem_head.next, struct mem_t, free_head);
	list_del_init(&mem->free_head);
	ptr = mem->mem;
	if(pool->mem_pool_mod == Mod_NO_MemId)
	{
		mem->mem = NULL;
	}
	list_add(&mem->use_head, &pool->use_mem_head);

	--pool->free_mem_num;
	++pool->use_mem_num;
	pool->free_pool_size -= pool->mem_size;
	pool->use_pool_size += pool->mem_size;

	if(mem_id && pool->mem_pool_mod != Mod_NO_MemId)
		*mem_id = (unsigned int)&mem->mem;
	return ptr;
}

int restore_mem_IdInset(MemPool *pool, void *ptr, unsigned int size)
{
	struct mem_t *m = NULL;
	MemId *mem_id;
	void **mp;
	
	if(!pool || !ptr || size != pool->mem_size)
		return -1;
//	if(pool->mem_pool_mod != Mod_MemId_InSet)
//		return -1;
	
	mem_id = (MemId *)ptr;
	mp = (void **)(*mem_id);
	if(*mp != ptr)
		return -1;
	
	m = list_entry(*mem_id, struct mem_t, mem);
	
	if( list_empty_careful(&m->use_head) )
		return -1;
	if( m->mem_size != size)
		return -1;
	
	list_del_init(&m->use_head);
	list_add(&m->free_head, &pool->free_mem_head);

	++pool->free_mem_num;
	--pool->use_mem_num;
	pool->free_pool_size += pool->mem_size;
	pool->use_pool_size -= pool->mem_size;

	return 0;
}

int restore_mem_IdOutset(MemPool *pool, MemId mem_id, unsigned int size)
{
	struct mem_t *m = NULL;
	
	if(!pool || size != pool->mem_size)
		return -1;
//	if(pool->mem_pool_mod != Mod_MemId_OutSet)
//		return -1;

	m = list_entry(mem_id, struct mem_t, mem);
	
	if( list_empty_careful(&m->use_head) )
		return -1;
	if( m->mem_size != size)
		return -1;

	list_del_init(&m->use_head);
	list_add(&m->free_head, &pool->free_mem_head);

	++pool->free_mem_num;
	--pool->use_mem_num;
	pool->free_pool_size += pool->mem_size;
	pool->use_pool_size -= pool->mem_size;

	return 0;
}

int restore_mem_IdOutset_safe(MemPool *pool, void *ptr, MemId mem_id, unsigned int size)
{
	struct mem_t *m = NULL;
	void **p_ptr = (void **)mem_id;
	
	if(!pool || !ptr || size != pool->mem_size)
		return -1;
//	if(pool->mem_pool_mod != Mod_MemId_OutSet)
//		return -1;
	if(*p_ptr != ptr)
		return -1;

	m = list_entry(mem_id, struct mem_t, mem);
	
	if( list_empty_careful(&m->use_head) )
		return -1;
	if( m->mem_size != size)
		return -1;
	
	list_del_init(&m->use_head);
	list_add(&m->free_head, &pool->free_mem_head);

	++pool->free_mem_num;
	--pool->use_mem_num;
	pool->free_pool_size += pool->mem_size;
	pool->use_pool_size -= pool->mem_size;

	return 0;
}

int restore_mem_NoId(MemPool *pool, void *ptr, unsigned int size)
{
	struct mem_t *m = NULL;
	
	if(!pool || !ptr || size != pool->mem_size)
		return -1;
//	if(pool->mem_pool_mod != Mod_NO_MemId)
//		return -1;
	
	if( list_empty_careful(&pool->use_mem_head) )
		return -1;
	
	m = list_entry(pool->use_mem_head.next, struct mem_t, use_head);
	
	if( m->mem_size != size)
		return -1;

	list_del_init(&m->use_head);
	m->mem = ptr;
	list_add(&m->free_head, &pool->free_mem_head);

	++pool->free_mem_num;
	--pool->use_mem_num;
	pool->free_pool_size += pool->mem_size;
	pool->use_pool_size -= pool->mem_size;

	return 0;
}

int restore_mem(MemPool *pool, void *ptr, MemId mem_id, unsigned int size)
{
	if(!pool || !pool->enable )
		return -1;

	switch(pool->mem_pool_mod)
	{
	case Mod_MemId_InSet:
		return restore_mem_IdInset(pool, ptr, size);
		break;
	case Mod_MemId_OutSet:
		if(ptr)
			return restore_mem_IdOutset_safe(pool, ptr, mem_id, size);
		else
			return restore_mem_IdOutset(pool, mem_id, size);
		break;
	case Mod_NO_MemId:
		return restore_mem_NoId(pool, ptr, size);
		break;
	}

	return -1;
}

enum MemPoolMod get_mempool_mod(MemPool *pool)	{return pool->mem_pool_mod;}
unsigned int get_all_memory(MemPool *pool)				{return pool->all_memory;}
unsigned int get_pool_size(MemPool *pool)				{return pool->pool_size;}
unsigned int get_mem_num(MemPool *pool)				{return pool->mem_num;}
unsigned int get_mem_size(MemPool *pool)				{return pool->mem_size;}
unsigned int get_free_pool_size(MemPool *pool)			{return pool->free_pool_size;}
unsigned int get_use_pool_size(MemPool *pool)			{return pool->use_pool_size;}
unsigned int get_free_mem_num(MemPool *pool)		{return pool->free_mem_num;}
unsigned int get_use_mem_num(MemPool *pool)			{return pool->use_mem_num;}




#define mem_cache_module_name_size		32
struct mem_cache_module
{
	//struct list_head mem_cache_head;
	struct list_head mem_pool_list;
	unsigned int pool_num;
	unsigned int all_pool_size;
	unsigned int all_free_pool_size;
	unsigned int all_mem_num;
	unsigned int all_free_mem_num;
	unsigned int mem_cache_all_memory;
	char name[mem_cache_module_name_size];
	mem_cache_call init;
	mem_cache_call fini;
	unsigned int enable;
};

struct mem_cache_manager
{
	struct mem_cache_module *mem_cache_list;
	unsigned int mem_cache_num;
	unsigned int cache_size;
	unsigned int total_size;
	unsigned int enable;
};

struct mem_cache_manager g_manager;


static int mem_cache_init_def(MemCacheModule *mcm)
{
	// add_mem_pool
	return MEMCACHE_CALL_OK;
}
static int mem_cache_fini_def(MemCacheModule *mcm)
{
	// remove_mem_pool
	return MEMCACHE_CALL_OK;
}
static void syn_mcmg_fore(MemCacheModule *mcm)
{
	g_manager.cache_size -= mcm->all_pool_size;
	g_manager.total_size -= mcm->mem_cache_all_memory;
}
static void syn_mcmg(MemCacheModule *mcm)
{
	g_manager.cache_size += mcm->all_pool_size;
	g_manager.total_size += mcm->mem_cache_all_memory;
}
static inline void syn_stat_fore(MemCacheModule *mcm, MemPool *pool)
{
	syn_mcmg_fore(mcm);
	mcm->all_free_mem_num -= pool->free_mem_num;
	mcm->all_free_pool_size -= pool->free_pool_size;
	mcm->all_mem_num -= pool->mem_num;
	mcm->all_pool_size -= pool->pool_size;
	mcm->mem_cache_all_memory -= pool->all_memory;
	syn_mcmg(mcm);
}
static inline void syn_stat(MemCacheModule *mcm, MemPool *pool)
{
	syn_mcmg_fore(mcm);
	mcm->all_free_mem_num += pool->free_mem_num;
	mcm->all_free_pool_size += pool->free_pool_size;
	mcm->all_mem_num += pool->mem_num;
	mcm->all_pool_size += pool->pool_size;
	mcm->mem_cache_all_memory += pool->all_memory;
	syn_mcmg(mcm);
}
static MemPool *find_mem_pool(MemCacheModule *mcm, unsigned int size)
{
	MemPool *pos;

	if( !list_empty_careful(&mcm->mem_pool_list))
	{
		list_for_each_entry(pos, &mcm->mem_pool_list, pool_head)
		{
			if(pos->mem_size == size)
				return pos;
		}
	}

	return NULL;
}
int remove_mem_pool(MemCacheModule *mcm, unsigned int mem_size)
{
	MemPool *pool = NULL;
	
	if(!mcm || !mcm->enable)
		return -1;

	pool = find_mem_pool(mcm, mem_size);
	if(pool)
	{
		DisEnable_MemPool(pool);
		list_del(&pool->pool_head);
		syn_stat_fore(mcm, pool);
		free_mem_pool(pool);
		return 0;
	}
	else
		return -1;
}
int remove_mem_pool_2(mcm_id id, unsigned int mem_size)
{
	MemCacheManager *manager = &g_manager;
	MemCacheModule *mcm;

	if(!manager->enable)
		return -1;
	if(id >= manager->mem_cache_num)
		return -1;
	mcm = &manager->mem_cache_list[id];
	
	return remove_mem_pool(mcm, mem_size);
}
static int __add_mem_pool(MemCacheModule *mcm, unsigned int mem_num, unsigned int mem_size, MemPool **cgPool)
{
	MemCacheManager *manager = &g_manager;
	MemPool *pool = NULL;
	int ret=0;
	unsigned int extend_mem_num=mem_num;

	if(cgPool)
		pool = *cgPool;
	else
		pool = find_mem_pool(mcm, mem_size);

	if(pool == NULL)
	{
		pool = new_mem_pool(mem_num, mem_size, Mod_NO_MemId);
		if(pool == NULL)
			return -1;
		list_add(&pool->pool_head, &mcm->mem_pool_list);
		++mcm->pool_num;
	}
	else
	{
		syn_stat_fore(mcm, pool);
		if( extend_mem_pool(pool, extend_mem_num) == NULL )
			ret = -1;
	}

	syn_stat(mcm, pool);

	if(cgPool)	*cgPool = pool;
	return ret;
}
int add_mem_pool(MemCacheModule *mcm, unsigned int mem_num, unsigned int mem_size)
{
	MemCacheManager *manager = &g_manager;

	if(!manager->enable)
		return -1;
	if(!mcm || !mcm->enable)
		return -1;

	return __add_mem_pool(mcm, mem_num, mem_size, NULL);
}
int add_mem_pool_2(mcm_id id, unsigned int mem_num, unsigned int mem_size)
{
	MemCacheManager *manager = &g_manager;
	MemCacheModule *mcm;

	if(!manager->enable)
		return -1;
	if(id >= manager->mem_cache_num)
		return -1;
	mcm = &manager->mem_cache_list[id];
	if(!mcm->enable)
		return -1;

	return __add_mem_pool(mcm, mem_num, mem_size, NULL);
}

static void __destory_mem_cache(MemCacheModule *mcm)
{
	MemCacheManager *manager = &g_manager;
	MemPool *pos, *n;
	
	mcm->enable = 0;
	if( !list_empty_careful(&mcm->mem_pool_list) )
	{
		list_for_each_entry_safe(pos, n, &mcm->mem_pool_list, pool_head)
			free_mem_pool(pos);
		INIT_LIST_HEAD(&mcm->mem_pool_list);
	}
	syn_mcmg_fore(mcm);
	mcm->all_free_mem_num = 0;
	mcm->all_free_pool_size = 0;
	mcm->all_mem_num = 0;
	mcm->all_pool_size = 0;
	mcm->mem_cache_all_memory = 0;
	mcm->pool_num = 0;
}
int destroy_mem_cache(mcm_id id)
{
	MemCacheManager *manager = &g_manager;
	MemCacheModule *mcm;
	int ret=0;

	if(!manager->enable)
		return -1;
	if(id >= manager->mem_cache_num)
		return -1;
	mcm = &manager->mem_cache_list[id];
	if(!mcm->enable)
		return 0;
	ret = mcm->fini(mcm);
	__destory_mem_cache(mcm);

	return ret;
}
static int destroy_all_mem_cache()
{
	int id, ret = 0, n;
	MemCacheModule *mcm;

	for(id=0; id<g_manager.mem_cache_num; id++)
	{
		mcm = &g_manager.mem_cache_list[id];
		if(!mcm->enable)
			continue;
		n = mcm->fini(mcm);
		if(n != MEMCACHE_CALL_OK)	ret += -1;
		__destory_mem_cache(mcm);
	}
	return ret;
}
int create_mem_cache(mcm_id id, const char *name, mem_cache_call init, mem_cache_call fini)
{
	MemCacheManager *manager = &g_manager;
	MemCacheModule *mcm;

	if(!manager->enable)
		return -1;
	if(id >= manager->mem_cache_num || strlen(name) > mem_cache_module_name_size)
		return -1;

	mcm = &manager->mem_cache_list[id];
	if(mcm->enable)
		return -1;
	
	INIT_LIST_HEAD(&mcm->mem_pool_list);
	//INIT_LIST_HEAD(&mcm->mem_cache_head);
	if(name)
		strcpy(mcm->name, name);
	else
		sprintf(mcm->name, "mem_cache_%d", id);
	if(init)
		mcm->init = init;
	else
		mcm->init = mem_cache_init_def;
	if(fini)
		mcm->fini = fini;
	else
		mcm->fini = mem_cache_fini_def;
	if( mcm->init(mcm) != MEMCACHE_CALL_OK )
		return -1;
	mcm->enable = 1;

	return 0;
}

void *mem_cache_alloc(mcm_id id, unsigned int size)
{
	MemCacheManager *manager = &g_manager;
	MemCacheModule *mcm;
	MemPool *pool = NULL, *pos;
	void *ret = NULL;

	if(!manager->enable)
		return NULL;
	if(id >= manager->mem_cache_num)
		return NULL;

	mcm = &manager->mem_cache_list[id];
	if(!mcm->enable)
		return NULL;

	pool = find_mem_pool(mcm, size);

	if(pool == NULL)
	{
		if( __add_mem_pool(mcm, 4, size, &pool) != 0 )
			return NULL;
	}

	syn_stat_fore(mcm, pool);
	ret = borrow_mem(pool, NULL);
	if(ret == NULL)
	{
		// can't use "if( __add_mem_pool(mcm, 4, size, &pool) != 0 )" 
		// because the statistical information will be influenced. 
		// __add_mem_pool can't use between syn_stat_fore and syn_stat
		if( extend_mem_pool(pool, 4) == NULL)	
			goto ALLOC_FAILED;
		ret = borrow_mem(pool, NULL);
		if(ret == NULL)
			goto ALLOC_FAILED;
	}
	
	syn_stat(mcm, pool);
	return ret;
	
ALLOC_FAILED:
	syn_stat(mcm, pool);
	return NULL;
}
int mem_cache_free(mcm_id id, void *data, unsigned int size)
{
	MemCacheManager *manager = &g_manager;
	MemCacheModule *mcm;
	MemPool *pool = NULL, *pos;
	int ret = -1;

	if(!manager->enable)
		return -1;
	if(id >= manager->mem_cache_num || data == NULL)
		return -1;

	mcm = &manager->mem_cache_list[id];
	if(!mcm->enable)
		return -1;

	pool = find_mem_pool(mcm, size);
	if(pool)
	{
		syn_stat_fore(mcm, pool);
		ret = restore_mem(pool, data, 0, size);
		syn_stat(mcm, pool);
	}

	return ret;
}

int lib_mem_cache_init(unsigned int module_max_num)
{
	unsigned int size;
	
	g_manager.enable = 0;
	g_manager.mem_cache_num = module_max_num;
	if(g_manager.mem_cache_num == 0)
		return -1;
	size = sizeof(MemCacheModule) * g_manager.mem_cache_num;
	g_manager.mem_cache_list = (MemCacheModule *)malloc(size);
	if(g_manager.mem_cache_list == NULL)
		return -1;
	memset(g_manager.mem_cache_list, 0, size);
	g_manager.cache_size = 0;
	g_manager.total_size = size;
	g_manager.enable = 1;
	
	return 0;
}

int lib_mem_cache_close()
{
	int ret=0;
	g_manager.enable = 0;
	ret = destroy_all_mem_cache();
	free(g_manager.mem_cache_list);
	g_manager.cache_size = 0;
	g_manager.mem_cache_num = 0;
	g_manager.total_size = 0;
	return ret;
}
static void print_mcm(MemCacheModule *mcm)
{
	printf("---- %s \n", mcm->name);
	printf("enable: %u \n", mcm->enable);
	printf("pool_num: %u \n", mcm->pool_num);
	printf("all_pool_size: %u \n", mcm->all_pool_size);
	printf("all_free_pool_size: %u \n", mcm->all_free_pool_size);
	printf("all_mem_num: %u \n", mcm->all_mem_num);
	printf("all_free_mem_num: %u \n", mcm->all_free_mem_num);
	printf("mem_cache_all_memory: %u \n", mcm->mem_cache_all_memory);
}
static void print_mem_cache()
{
	int id;
	
	printf("------ mem cache ------\n");
	printf("mem_cache_num: %u \n", g_manager.mem_cache_num);
	printf("cache_size: %u \n", g_manager.cache_size);
	printf("total_size: %u \n", g_manager.total_size);
	for(id=0; id<g_manager.mem_cache_num; id++)
		print_mcm(&g_manager.mem_cache_list[id]);
	printf("---------------------------\n");
}


unsigned int get_mcmg_total_size()	{return g_manager.total_size;}
unsigned int get_mcmg_cache_size()	{return g_manager.cache_size;}
unsigned int get_mcm_pool_num(mcm_id id)
{
	if(id >= g_manager.mem_cache_num)	return 0;
	return g_manager.mem_cache_list[id].pool_num;
}
unsigned int get_mcm_all_pool_size(mcm_id id)
{
	if(id >= g_manager.mem_cache_num)	return 0;
	return g_manager.mem_cache_list[id].all_pool_size;
}
unsigned int get_mcm_all_free_pool_size(mcm_id id)
{
	if(id >= g_manager.mem_cache_num)	return 0;
	return g_manager.mem_cache_list[id].all_free_pool_size;
}
unsigned int get_mcm_all_mem_num(mcm_id id)
{
	if(id >= g_manager.mem_cache_num)	return 0;
	return g_manager.mem_cache_list[id].all_mem_num;
}
unsigned int get_mcm_all_free_mem_num(mcm_id id)
{
	if(id >= g_manager.mem_cache_num)	return 0;
	return g_manager.mem_cache_list[id].all_free_mem_num;
}
unsigned int get_mcm_mem_cache_all_memory(mcm_id id)
{
	if(id >= g_manager.mem_cache_num)	return 0;
	return g_manager.mem_cache_list[id].mem_cache_all_memory;
}

#if 0
struct test_t
{
	MemId mem_id;
	int a;
	int b;
	char c[16];
	int d;
	char e;
};

#define pprint(fmt, ...)	printf(">> "fmt, ##__VA_ARGS__)

#define exit_error(str)	do { \
	pprint("%s\n", str); \
	pprint("exit: %s [%d] \n", __FILE__, __LINE__); \
	exit(0); \
} while (0)

MemPool *test_pool;
struct test_t *p_test, *p_test_2, *p_test_3;
unsigned int mem_id, mem_id_2;

void mod_memid_inset()
{
	int ret;
	printf("-------------  test mod_memid_inset   -----\n");
	
	test_pool = new_mem_pool(128, sizeof(struct test_t), Mod_MemId_InSet);
	if(!test_pool)
		exit_error("new_mem_pool error");
	print_mem_pool(test_pool);
	extend_mem_pool(test_pool, 4);
	print_mem_pool(test_pool);

	p_test = (struct test_t *)borrow_mem(test_pool, NULL);
	print_mem_pool(test_pool);
	
	p_test_2 = borrow_mem_type(test_pool, struct test_t, NULL);
	print_mem_pool(test_pool);

	ret = restore_mem(test_pool, p_test, 0, sizeof(struct test_t));
	if(ret<0)	pprint("restore_mem error \n");
	ret = restore_mem(test_pool, p_test_2, 0, sizeof(struct test_t));
	if(ret<0)	pprint("restore_mem error \n");

	print_mem_pool(test_pool);

	free_mem_pool(test_pool);
}

void mod_memid_outset()
{
	int ret;
	printf("-------------  test mod_memid_outset   -----\n");
	
	test_pool = new_mem_pool(128, sizeof(struct test_t), Mod_MemId_OutSet);
	if(!test_pool)
		exit_error("new_mem_pool error");
	print_mem_pool(test_pool);
	extend_mem_pool(test_pool, 4);
	print_mem_pool(test_pool);

	p_test = (struct test_t *)borrow_mem(test_pool, &mem_id);
	print_mem_pool(test_pool);
	
	p_test_2 = borrow_mem_type(test_pool, struct test_t, &mem_id_2);
	print_mem_pool(test_pool);

	ret = restore_mem(test_pool, p_test, mem_id, sizeof(struct test_t));
	if(ret<0)	pprint("restore_mem error \n");
	ret = restore_mem(test_pool, NULL, mem_id_2, sizeof(struct test_t));
	if(ret<0)	pprint("restore_mem error \n");

	print_mem_pool(test_pool);

	free_mem_pool(test_pool);
}

void mod_no_memid()
{
	int ret;
	printf("-------------  test mod_no_memid   -----\n");
	
	test_pool = new_mem_pool(128, sizeof(struct test_t), Mod_NO_MemId);
	if(!test_pool)
		exit_error("new_mem_pool error");
	print_mem_pool(test_pool);
	extend_mem_pool(test_pool, 4);
	print_mem_pool(test_pool);

	p_test = (struct test_t *)borrow_mem(test_pool, NULL);
	print_mem_pool(test_pool);
	
	p_test_2 = borrow_mem_type(test_pool, struct test_t, NULL);
	print_mem_pool(test_pool);

	p_test_3 = borrow_mem_type(test_pool, struct test_t, NULL);
	print_mem_pool(test_pool);

	ret = restore_mem(test_pool, p_test, 0, sizeof(struct test_t));
	if(ret<0)	pprint("restore_mem error \n");
	ret = restore_mem(test_pool, p_test_2, 0, sizeof(struct test_t));
	if(ret<0)	pprint("restore_mem error \n");

	print_mem_pool(test_pool);

	free_mem_pool(test_pool);
	free(p_test_3 );
}

struct mc_test
{
	int a, b, c, d;
};
struct mc_test *mc_1, *mc_2, *mc_3;
void mem_cache_test()
{
#define MOD_A	0
#define MOD_B	1
	int ret;
printf("*********** lib_mem_cache_init ********** \n");
	ret = lib_mem_cache_init(2);
	if(ret < 0)	printf("lib_mem_cache_init failed \n");
printf("*********** create_mem_cache ********** \n");
	ret = create_mem_cache(MOD_A, "mod A", NULL, NULL);
	if(ret < 0)	printf("create_mem_cache failed \n");
	ret = create_mem_cache(MOD_B, "mod B", NULL, NULL);
	if(ret < 0)	printf("create_mem_cache failed \n");
	print_mem_cache();
printf("*********** mem_cache_alloc ********** \n");
	p_test = (struct test_t *)mem_cache_alloc(MOD_A, sizeof(struct test_t));
	if(p_test == NULL)	printf("mem_cache_alloc failed \n");
	p_test_2 = (struct test_t *)mem_cache_alloc(MOD_A, sizeof(struct test_t));
	if(p_test_2 == NULL)	printf("mem_cache_alloc failed \n");
	mc_1 = (struct mc_test *)mem_cache_alloc(MOD_A, sizeof(struct mc_test));
	if(mc_1 == NULL)	printf("mem_cache_alloc failed \n");
	mc_2 = (struct mc_test *)mem_cache_alloc(MOD_A, sizeof(struct mc_test));
	if(mc_2 == NULL)	printf("mem_cache_alloc failed \n");
	mc_3 = (struct mc_test *)mem_cache_alloc(MOD_B, sizeof(struct mc_test));
	if(mc_3 == NULL)	printf("mem_cache_alloc failed \n");
	print_mem_cache();
printf("*********** mem_cache_free ********** \n");
	ret = mem_cache_free(MOD_A, p_test, sizeof(struct test_t));
	if(ret < 0)	printf("mem_cache_free failed \n");
	ret = mem_cache_free(MOD_A, p_test_2, sizeof(struct test_t));
	if(ret < 0)	printf("mem_cache_free failed \n");
	ret = mem_cache_free(MOD_A, mc_1, sizeof(struct mc_test));
	if(ret < 0)	printf("mem_cache_free failed \n");
	ret = mem_cache_free(MOD_A, mc_2, sizeof(struct mc_test));
	if(ret < 0)	printf("mem_cache_free failed \n");
	ret = mem_cache_free(MOD_B, mc_3, sizeof(struct mc_test));
	if(ret < 0)	printf("mem_cache_free failed \n");
	print_mem_cache();
printf("*********** add_mem_pool_2 ********** \n");
	ret = add_mem_pool_2(MOD_B, 2, sizeof(struct mc_test));
	if(ret < 0)	printf("add_mem_pool_2 failed \n");
	print_mem_cache();
	ret = add_mem_pool_2(MOD_B, 2, sizeof(struct test_t));
	if(ret < 0)	printf("add_mem_pool_2 failed \n");
	print_mem_cache();
printf("*********** remove_mem_pool_2 ********** \n");
	ret = remove_mem_pool_2(MOD_B, sizeof(struct mc_test));
	if(ret < 0)	printf("remove_mem_pool_2 failed \n");
	print_mem_cache();
printf("*********** destroy_mem_cache ********** \n");
	ret = destroy_mem_cache(MOD_B);
	if(ret < 0)	printf("destroy_mem_cache failed \n");
	print_mem_cache();
printf("*********** lib_mem_cache_close ********** \n");
	ret = lib_mem_cache_close();
	if(ret < 0)	printf("lib_mem_cache_close failed \n");
	print_mem_cache();
}

void main()
{

	//mod_memid_inset();
	//mod_memid_outset();
	mod_no_memid();

	//mem_cache_test();
}


#endif

