#ifndef BB_WGET_THREAD_H_
#define BB_WGET_THREAD_H_

#include "bb_wget_lib.h"

// 0: dead ; >0: alive ; <0: error
extern int wf_get_thread_state(pthread_t *p_tid);


#include <pthread.h>

#define BBWGET_THREAD_SIGQUIT SIGUSR1

typedef struct bb_wget_thread_s{
	pthread_t tid;
	void *private_data;
	void *extend_ptr;
	void (*extend_ptr_free)(void *ptr);
}bb_wget_thread_t;

extern void bb_wget_thread_t_free(bb_wget_thread_t *ptr, int free_self);

extern void lib_bbwget_thread_destroy(bb_wget_thread_t *bbwget_thd, int wait);
extern void lib_bbwget_thread_join_destroy(bb_wget_thread_t *bbwget_thd);

// 0: dead ; >0: alive ; <0: error
extern int lib_bbwget_thread_state(bb_wget_thread_t *bbwget_thd);

extern bb_wget_thread_t *lib_bbwget_thread(bb_wget_lib_t *set, int argc, char **argv, pthread_attr_t	*attr);

extern bb_wget_thread_t *lib_bbwget_to_wf_buffer_thread(int argc, char **argv, pthread_attr_t	*attr, struct wf_buffer **out, unsigned int buffer_size);

extern int lib_bbwget_check_url_exist_wait_100usec(char * url, unsigned int max_count);


#endif

