#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/sysinfo.h>
#include <sys/param.h>
#include <sys/time.h>

//#include "config.h"
#include "thread_timer.h"
//#include "utils.h"

static struct list_head timers;
static struct list_head free_timers;

pthread_mutex_t timer_tlock;

time_t current_time;

static pthread_key_t timer_key;
static pthread_once_t timer_key_once = PTHREAD_ONCE_INIT;
static void make_timer_key()
{
	pthread_key_create(&timer_key, NULL);
}

static struct list_head *get_timer_head()
{
    struct list_head *head ;

	if ((head = pthread_getspecific(timer_key)) == NULL) {
		head = malloc(sizeof(struct list_head));
		if (!head){
			fprintf(stderr,"no such timer head!\n");
			return NULL;
		}
		INIT_LIST_HEAD(head);
		pthread_setspecific(timer_key, head);
	}
	return head ;
	
}


int init_timer (void)
{
	INIT_LIST_HEAD(&timers);
	INIT_LIST_HEAD(&free_timers);

	//timer_tlock = PTHREAD_MUTEX_INITIALIZER;
	pthread_mutex_init(&timer_tlock, NULL);

    pthread_once(&timer_key_once, make_timer_key);

	update_curr_time();
	return 0;
}

#define WRAPAROUND_VALUE (0xffffffffUL / HZ + 1) /* HZ = frequency of ticks
                                                    per second. */


struct timeval timeval_adjust (struct timeval a)
{
	while (a.tv_usec >= TV_USEC_PER_SEC)
	{
		a.tv_usec -= TV_USEC_PER_SEC;
		a.tv_sec++;
	}
	
	while (a.tv_usec < 0)
	{
		a.tv_usec += TV_USEC_PER_SEC;
		a.tv_sec--;
	}
	
	if (a.tv_sec < 0)
	{
		a.tv_sec = 0;
		a.tv_usec = 10;
	}
	
	if (a.tv_sec > TV_USEC_PER_SEC)
		a.tv_sec = TV_USEC_PER_SEC;
	
	return a;
}
	
struct timeval timeval_subtract (struct timeval a, struct timeval b)
{
	struct timeval ret;

	ret.tv_usec = a.tv_usec - b.tv_usec;
	ret.tv_sec = a.tv_sec - b.tv_sec;

	return timeval_adjust (ret);
}
	

int timeval_cmp (struct timeval a, struct timeval b)
{
	return (a.tv_sec == b.tv_sec ?
		a.tv_usec - b.tv_usec : a.tv_sec - b.tv_sec);
}

/* Static function to get current sec and usec.  */

static int
system_uptime (struct timeval *tv, struct timezone *tz)
{
	struct sysinfo info;
	static unsigned long prev = 0;
	static unsigned long wraparound_count = 0;
	unsigned long uptime;
	static long base = 0;
	static long offset = 0;
	long leap;
	long diff;
  
	/* Get sysinfo.  */
	if (sysinfo (&info) < 0)
		return -1;

	/* Check for wraparound. */
	if (prev > info.uptime)
		wraparound_count++;
  
	/* System uptime.  */
	uptime = wraparound_count * WRAPAROUND_VALUE + info.uptime;
	prev = info.uptime;      
  
	/* Get tv_sec and tv_usec.  */
	gettimeofday (tv, tz);

	/* Deffernce between gettimeofday sec and uptime.  */
	leap = tv->tv_sec - uptime;

	/* Remember base diff for adjustment.  */
	if (! base)
		base = leap;

	/* Basically we use gettimeofday's return value because it is the
		only way to get required granularity.  But when diff is very
		different we adjust the value using base value.  */
	diff = (leap - base) + offset;

	/* When system time go forward than 2 sec.  */
	if (diff > 2 || diff < -2)
		offset -= diff;

	/* Adjust second.  */
	tv->tv_sec += offset;

	return 0;
}

/* There is a case that system time is changed.  */
void get_time_tzcurrent (struct timeval *tv,
		    struct timezone *tz)
{
	pthread_mutex_lock(&timer_tlock);
	system_uptime (tv, tz);
	pthread_mutex_unlock(&timer_tlock);
  return;
}

static time_t get_time(void)
{
	struct timeval tv;
	int ret;
	
	/* Get current time i.e. time since reboot. */
	ret = system_uptime (&tv, NULL);
	if (ret != 0)
		return -1;
	
	/* When argument is specified copy value.  */
	return (time_t)tv.tv_sec;
}

time_t get_curr_time(void )
{
	time_t ret;
	pthread_mutex_lock(&timer_tlock);
	ret = current_time;
	pthread_mutex_unlock(&timer_tlock);
	
	return ret;
}
time_t update_curr_time(void )
{
	time_t ret;
	pthread_mutex_lock(&timer_tlock);
	ret = current_time = get_time();
	pthread_mutex_unlock(&timer_tlock);
	return ret;
}

static struct timer_entry * alloc_timer()
{
	struct timer_entry * q = NULL;
	struct list_head * pos;
	pthread_mutex_lock(&timer_tlock);
	if (!list_empty(&free_timers)) {
		pos = free_timers.next;
		list_del(pos);
		q = list_entry(pos,struct timer_entry,list);
		bzero(q,sizeof(struct timer_entry));
	} else {
		q = (struct timer_entry *)calloc (1, sizeof (struct timer_entry));
		if (!q)
			fprintf(stderr,"Can't allocate timer structure!");
	}
	pthread_mutex_unlock(&timer_tlock);
	INIT_LIST_HEAD(&q->list);

	return q;
}

static void free_timer(struct timer_entry *q)
{
	if (q) {
		pthread_mutex_lock(&timer_tlock);
		list_add(&q->list,&free_timers);
		pthread_mutex_unlock(&timer_tlock);
	}
}

static int add_timer_entry (struct list_head *head, struct timer_entry *entry)
{

    struct timer_entry *pos = NULL;
	struct timeval when;
  	if (!entry) {
		fprintf(stderr,"error pointer!!\n");
		goto out;
	}
	/* Do we need jitter here? */
	get_time_tzcurrent (&when, NULL);
	when.tv_usec += entry->interval*1000;
	while (when.tv_usec >= TV_USEC_PER_SEC) {
		when.tv_sec++;
		when.tv_usec -= TV_USEC_PER_SEC;
	}

  /* Correct negative value.  */
  if (when.tv_sec < 0)
    when.tv_sec = PAL_TIME_MAX_TV_SEC;
  if (when.tv_usec < 0)
    when.tv_usec = PAL_TIME_MAX_TV_USEC;

	entry->when = when;

	list_for_each_entry(pos, head, list) {
		if (timeval_cmp(entry->when , pos->when) < 0) {
            break;
		}
	}
	list_add_tail(&entry->list,&pos->list);
out:
    return 0;

}

/*return millisecond */
static long get_timer_wait (long *timeout)
{
	struct timeval timer_now;
	struct timeval timer_min;
	struct timeval *timer_wait;
	struct list_head *head;
  
	timer_wait = NULL;
	head = get_timer_head();

	if (!list_empty(head)) {
		timer_wait = &((list_entry(head->next,struct timer_entry,list))->when);
	}
	
	if (timer_wait) {
  	
		timer_min = *timer_wait;

		get_time_tzcurrent (&timer_now, NULL);
		
		timer_min = timeval_subtract (timer_min, timer_now);

		if (timer_min.tv_sec < 0) {
			timer_min.tv_sec = 0;
			timer_min.tv_usec = 10;
		}

		*timeout = timer_min.tv_sec*1000 + timer_min.tv_usec/1000+1;
		return *timeout;
	}
	/*default one second*/
	return 1000;
}

void process_timer (long *timeout)
{
	struct timer_entry *pos = NULL,*n = NULL;
	struct list_head *head;
	struct timeval timer_now;
	LIST_HEAD(tmp_list);
	

	head = get_timer_head();

	get_time_tzcurrent(&timer_now, NULL);

	//now = current_time;
	list_for_each_entry_safe(pos, n,head, list){
		if (timeval_cmp(pos->when , timer_now) <= 0){
			(*pos->func) (pos->data);
			if (pos->cycle){
				list_del(&pos->list);
				list_add(&pos->list,&tmp_list);
			}else{
				del_timer(pos);
			}
		} else {
			break;
		}
	}
	list_for_each_entry_safe(pos, n,&tmp_list, list){
		list_del(&pos->list);
//		pos->when = timer_now + pos->interval;
		add_timer_entry(head, pos);
	}
	
	/*debug*/
	/*list_for_each_entry(pos, &timers, list){
		fprintf(stderr," timer when = %lu\n",pos->when);
	}*/
	if (timeout) {
		get_timer_wait(timeout);
	}
	return;
}



struct timer_entry *add_timer (long interval,int cycle,void (*func) (void *),
                                 void *data)
{

	struct timer_entry *new = NULL;
	struct list_head *head;
  
	new = alloc_timer();
	if (!new){
		goto out;
	}
	head = get_timer_head();
	
	INIT_LIST_HEAD(&new->list);
    new->func 		= func;
    new->data 		= data;
//	new->when 		= when;
	new->interval 	= interval;
	new->cycle 		= cycle;
	add_timer_entry(head,new);
out:
    return new;

}



void del_timer (struct timer_entry *s)
{
    list_del(&s->list);
	free_timer(s);
}


