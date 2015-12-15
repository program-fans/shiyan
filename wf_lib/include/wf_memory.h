#ifndef WF_MEMORY_H_
#define WF_MEMORY_H_

typedef struct mem_pool MemPool;
typedef unsigned int MemId;

enum MemPoolMod
{
	Mod_MemId_OutSet,
	Mod_MemId_InSet,
	Mod_NO_MemId
};

#define Enable_MemPool(pool)			pool->enable = 1;
#define DisEnable_MemPool(pool)		pool->enable = 0;

/*
[in]
@mem_num: the count of memory (struct user_struct)
@mem_size: the size of memory (struct user_struct)
	pool_size = mem_num + mem_size
@mod: MemPoolMod
	if MemPoolMod set Mod_MemId_OutSet, then MemId must be saved by user.
	if MemPoolMod set Mod_MemId_InSet, then MemId must be the first member of user_struct.
		struct user_struct
		{
			MemId mem_id;
			int user_data;
		};
	if MemPoolMod set Mod_NO_MemId, then no MemId.
		This case, if memory has not been restored, then the memory must be free by user.
[return]
!NULL:	the pointer of MemPool
NULL:	failed
*/
extern MemPool *new_mem_pool(unsigned int mem_num, unsigned int mem_size, enum MemPoolMod mod);

/*
[in]
@pool: the pointer of MemPool
@mem_num: the count of extend memory (struct user_struct)
[return]
!NULL:	the pointer of MemPool (@pool)
NULL:	failed
		if failed, nothing for pool, pool is not change*/
extern MemPool *extend_mem_pool(MemPool *pool, unsigned int mem_num);

/*
[in]
@pool: the pointer of MemPool
	if MemPoolMod set Mod_NO_MemId, 
		if memory has not been restored, then the memory will not be free by this function.
		the memory must be free by user.
	if MemPoolMod set Mod_MemId_OutSet and Mod_MemId_InSet, 
		if memory has not been restored, then the memory will be free by this function.
*/
extern void free_mem_pool(MemPool *pool);

/*
[in]
@pool: the pointer of MemPool
[out]
@mem_id: mem_id used by restore_mem and restore_mem_safe.
	if MemPoolMod set Mod_MemId_OutSet, then mem_id must be not NULL.
	if MemPoolMod set Mod_MemId_InSet, then mem_id can be NULL.
	if MemPoolMod set Mod_NO_MemId, then mem_id is no-use.
[return]
!NULL: 	the pointer of memory (Not initialized)
NULL: 	failed, param error or no free memory
*/
extern void *borrow_mem(MemPool *pool, MemId *mem_id);
#define borrow_mem_type(pool, type, p_mem_id)		(type *)borrow_mem(pool, p_mem_id)

/*
[in]
@pool: the pointer of MemPool
@ptr: the pointer of memory (struct user_struct)
	if MemPoolMod set Mod_MemId_OutSet, then ptr can be NULL. But not recommend.
	if MemPoolMod set Mod_MemId_InSet and Mod_NO_MemId, then ptr must be not NULL.
@mem_id: the key of memory (struct user_struct)
	if MemPoolMod set Mod_MemId_OutSet, then mem_id must be effective.
	if MemPoolMod set Mod_MemId_InSet, then mem_id is not necessary.
	if MemPoolMod set Mod_NO_MemId, then mem_id is no-use.
@size: the size of memory (struct user_struct)
[return]
0: 	success
-1: 	failed
*/
extern int restore_mem(MemPool *pool, void *ptr, MemId mem_id, unsigned int size);

extern enum MemPoolMod get_mempool_mod(MemPool *pool);
extern unsigned int get_all_memory(MemPool *pool);
extern unsigned int get_pool_size(MemPool *pool);
extern unsigned int get_mem_num(MemPool *pool);
extern unsigned int get_mem_size(MemPool *pool);
extern unsigned int get_free_pool_size(MemPool *pool);
extern unsigned int get_use_pool_size(MemPool *pool);
extern unsigned int get_free_mem_num(MemPool *pool);
extern unsigned int get_use_mem_num(MemPool *pool);




#define MEMCACHE_CALL_OK		0
#define MEMCACHE_CALL_FAILED	-1

typedef struct mem_cache_module MemCacheModule;
typedef unsigned int mcm_id;									// the id of module
typedef struct mem_cache_manager MemCacheManager;
typedef int(*mem_cache_call)(MemCacheModule *);

/*
use this function in mem_cache_call.
*/
extern int remove_mem_pool(MemCacheModule *mcm, unsigned int mem_size);

extern int remove_mem_pool_2(mcm_id id, unsigned int mem_size);

/*
use this function in mem_cache_call.
*/
extern int add_mem_pool(MemCacheModule *mcm, unsigned int mem_num, unsigned int mem_size);

extern int add_mem_pool_2(mcm_id id, unsigned int mem_num, unsigned int mem_size);



extern int destroy_mem_cache(mcm_id id);

extern int create_mem_cache(mcm_id id, const char *name, mem_cache_call init, mem_cache_call fini);

extern void *mem_cache_alloc(mcm_id id, unsigned int size);

extern int mem_cache_free(mcm_id id, void *data, unsigned int size);

/*
[in]
@module_max_num: the count of modules.  0 <= mcm_id < module_max_num.
*/
extern int lib_mem_cache_init(unsigned int module_max_num);

extern int lib_mem_cache_close();


extern unsigned int get_mcmg_total_size();
extern unsigned int get_mcmg_cache_size();
extern unsigned int get_mcm_pool_num(mcm_id id);
extern unsigned int get_mcm_all_pool_size(mcm_id id);
extern unsigned int get_mcm_all_free_pool_size(mcm_id id);
extern unsigned int get_mcm_all_mem_num(mcm_id id);
extern unsigned int get_mcm_all_free_mem_num(mcm_id id);
extern unsigned int get_mcm_mem_cache_all_memory(mcm_id id);

#endif

