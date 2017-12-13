#ifndef BB_WGET_LIB_H_
#define BB_WGET_LIB_H_

#include <stdio.h>

#undef PTHREAD_CANCEL_ENABLE	// for test
#define NOT_USE_PTHREAD_CREATE_DETACHED

typedef struct bb_wget_info_s{
//	int state;
	int targe_file_size;
//	unsigned long long int download_size;
}bb_wget_info_t;

typedef struct bb_wget_lib_s
{
	unsigned char no_output_file;
	unsigned char use_sigsetjmp;
#ifdef LIB_BBWGET_FOR_THREAD
	unsigned char is_loop;
	unsigned char need_exit;
#endif
	long set_beg_range_bytes;
	int (*output_write)(void *ptr, int size, struct bb_wget_lib_s *pwgetlib);
	void *extend_ptr;
	bb_wget_info_t info;
}bb_wget_lib_t;

extern int lib_bbwget_main(bb_wget_lib_t *set, int argc, char **argv);

#include "wf_char.h"

extern int lib_bbwget_to_wf_buffer(int argc, char **argv, struct wf_buffer **out, unsigned int buffer_size);


extern int lib_bbwget_check_url_exist(char *url);

#ifdef LIB_BBWGET_FOR_THREAD


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

// 0: dead ; >0: alive ; <0: error
extern int lib_bbwget_thread_state(bb_wget_thread_t *bbwget_thd);

extern bb_wget_thread_t *lib_bbwget_thread(bb_wget_lib_t *set, int argc, char **argv, pthread_attr_t	*attr);

extern bb_wget_thread_t *lib_bbwget_to_wf_buffer_thread(int argc, char **argv, pthread_attr_t	*attr, struct wf_buffer **out, unsigned int buffer_size);

extern int lib_bbwget_check_url_exist_wait_100usec(char * url, unsigned int max_count);

#endif


#endif

