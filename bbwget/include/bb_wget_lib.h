#ifndef BB_WGET_LIB_H_
#define BB_WGET_LIB_H_

#include <stdio.h>

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

#endif

