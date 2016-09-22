#ifndef THREAD_TIMER_H__
#define THREAD_TIMER_H__


#include "linux_list.h"
#include <time.h>
#include <sys/time.h>


/*
** Number of tv_usec per second.  Some systems actually purport to prefer
** nanosecond values for the tv_usec field.  Somehow, this probably isn't
** quite accurate yet...
*/
#define TV_USEC_PER_SEC 1000000

#define PAL_TIME_MAX_TV_SEC 0x7fffffff
#define PAL_TIME_MAX_TV_USEC 0x7fffffff

struct timer_entry {
	struct list_head list;
	struct timeval when;
	long interval;
	int cycle;
	void (*func) (void *);
	void *data;
};

/*#define TIME_LESS(a,b) ((a) < (b))
#define TIME_LESSEQ(a,b) ((a) <= (b))
#define TIME_GT(a,b) ((a) > (b))*/



extern time_t current_time;

int init_timer (void);
struct timeval timeval_subtract (struct timeval a, struct timeval b);
int timeval_cmp (struct timeval a, struct timeval b);
void get_time_tzcurrent (struct timeval *tv,
		    struct timezone *tz);
time_t get_curr_time();
time_t update_curr_time();

struct timer_entry *add_timer (long interval,int cycle,void (*func) (void *),
                                 void *data);
void del_timer (struct timer_entry *s);
void process_timer (long *timeout);


#endif

