/* Copyright (C) 2001-2003 IP Infusion, Inc. All Rights Reserved. */
#include <stdio.h>
#include <sys/sysinfo.h>
#include <sys/param.h>
#include <unistd.h>
#include <memory.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "libpx_thread.h"

#undef assert
#define assert(exp)		// nothing

#undef pal_mem_set
#define pal_mem_set memset

#undef pal_mem_cpy
#define pal_mem_cpy memcpy

#undef pal_mem_cmp
#define pal_mem_cmp memcmp

#undef pal_mem_move
#define pal_mem_move memmove

#define pal_sock_set_t                  fd_set
#define PAL_SOCKSET_SIZE                FD_SETSIZE
#define PAL_SOCK_HANDLESET_ISSET(h,s)   FD_ISSET(h,s)
#define PAL_SOCK_HANDLESET_SET(h,s)     FD_SET(h,s)
#define PAL_SOCK_HANDLESET_CLR(h,s)     FD_CLR(h,s)


typedef unsigned int  u_int32_t;

/*
   Thread.c maintains a list of all the "callbacks" waiting to run.

   It is RTOS configurable with "HAVE_RTOS_TIC", "HAVE_RTOS_TIMER",
   "RTOS_EXECUTE_ONE_THREAD".

   For Linux/Unix, all the above are undefined; the main task will
   just loop continuously on "thread_fetch" and "thread_call".
   "thread_fetch" will stay in a tight loop until all active THREADS
   are run.

   When "HAVE_RTOS_TIC" is defined, the RTOS is expected to emulate
   the "select" function as non-blocking, and call "lib_tic" for any
   I/O ready (by setting PAL_SOCK_HANDLESET_ISSET true), and must call
   "lib_tic" at least once every 1 second.

   When "HAVE_RTOS_TIMER" is defined, the RTOS must support the
   "rtos_set_timer( )", and set a timer; when it expires, it must call
   "lib_tic ( )".

   When "RTOS_EXECUTE_ONE_THREAD" is defined, the RTOS must treat
   ZebOS as strict "BACKGROUND".  The BACKGROUND MANAGER Keeps track
   of all ZebOS Routers, and calls them in strict sequence.  When
   "lib_tic" is called, ONLY ONE THREAD will be run, and a TRUE state
   will be SET to indicate that a THREAD has RUN, so the BACKGROUND
   should give control to the FOREGROUND once again.  If not SET, the
   BACKGROUND is allowed to go onto another Router to try its THREAD
   and so-forth, through all routers.
*/

struct pal_timeval
timeval_adjust (struct pal_timeval a)
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

struct pal_timeval
timeval_subtract (struct pal_timeval a, struct pal_timeval b)
{
  struct pal_timeval ret;

  ret.tv_usec = a.tv_usec - b.tv_usec;
  ret.tv_sec = a.tv_sec - b.tv_sec;

  return timeval_adjust (ret);
}

int
timeval_cmp (struct pal_timeval a, struct pal_timeval b)
{
  return (a.tv_sec == b.tv_sec ?
          a.tv_usec - b.tv_usec : a.tv_sec - b.tv_sec);
}

/* Allocate new thread master.  */
struct thread_master *thread_master_create ()
{
	struct thread_master * thread = (struct thread_master *) malloc (sizeof (struct thread_master));
	if(thread)
		memset(thread, 0, sizeof(struct thread_master));

	return thread;
}

/* Add a new thread to the list.  */
void thread_list_add (struct thread_list *list, struct thread *thread)
{
  thread->next = NULL;
  thread->prev = list->tail;
  if (list->tail)
    list->tail->next = thread;
  else
    list->head = thread;
  list->tail = thread;
  list->count++;
}

/* Add a new thread just after the point. If point is NULL, add to top. */
static void thread_list_add_after (struct thread_list *list, struct thread *point, struct thread *thread)
{
  thread->prev = point;
  if (point)
    {
      if (point->next)
        point->next->prev = thread;
      else
        list->tail = thread;
      thread->next = point->next;
      point->next = thread;
    }
  else
    {
      if (list->head)
        list->head->prev = thread;
      else
        list->tail = thread;
      thread->next = list->head;
      list->head = thread;
    }
  list->count++;
}

/* Delete a thread from the list. */
static struct thread *thread_list_delete (struct thread_list *list, struct thread *thread)
{
  if (thread->next)
    thread->next->prev = thread->prev;
  else
    list->tail = thread->prev;
  if (thread->prev)
    thread->prev->next = thread->next;
  else
    list->head = thread->next;
  thread->next = thread->prev = NULL;
  list->count--;
  return thread;
}

/* Delete top of the list and return it. */
static struct thread *thread_trim_head (struct thread_list *list)
{
  if (list->head)
    return thread_list_delete (list, list->head);
  return NULL;
}

/* Move thread to unuse list. */
static void thread_add_unuse (struct thread_master *m, struct thread *thread)
{
  assert (m != NULL);
  assert (thread->next == NULL);
  assert (thread->prev == NULL);
  assert (thread->type == THREAD_UNUSED);
  thread_list_add (&m->unuse, thread);
}

/* Free all unused thread. */
static void thread_list_free (struct thread_master *m, struct thread_list *list)
{
  struct thread *t;
  struct thread *next;

  for (t = list->head; t; t = next)
    {
      next = t->next;
      free (t);
      list->count--;
      m->alloc--;
    }
}

void thread_list_execute (struct thread_master *master, struct thread_list *list)
{
  struct thread *thread;

  thread = thread_trim_head (list);
  if (thread != NULL)
    {
      thread_execute (master, thread->func, thread->arg, thread->u.val);
      thread->type = THREAD_UNUSED;
      thread_add_unuse (master, thread);
    }
}

void thread_list_clear (struct thread_master *master, struct thread_list *list)
{
  struct thread *thread;

  while ((thread = thread_trim_head (list)))
    {
      thread->type = THREAD_UNUSED;
      thread_add_unuse (master, thread);
    }
}

/* Stop thread scheduler. */
void thread_master_finish (struct thread_master *m)
{
  int i;

  thread_list_free (m, &m->queue_high);
  thread_list_free (m, &m->queue_middle);
  thread_list_free (m, &m->queue_low);
  thread_list_free (m, &m->read);
  thread_list_free (m, &m->read_high);
  thread_list_free (m, &m->write);
  for (i = 0; i < THREAD_TIMER_SLOT; i++)
    thread_list_free (m, &m->timer[i]);
  thread_list_free (m, &m->event);
  thread_list_free (m, &m->event_low);
  thread_list_free (m, &m->unuse);

  free (m);
}

/* Thread list is empty or not.  */
int thread_empty (struct thread_list *list)
{
  return  list->head ? 0 : 1;
}

/* Return remain time in second. */
u_int32_t thread_timer_remain_second (struct thread *thread)
{
  struct pal_timeval timer_now;

  if (thread == NULL)
    return 0;

  pal_time_tzcurrent (&timer_now, NULL);

  if (thread->u.sands.tv_sec - timer_now.tv_sec > 0)
    return thread->u.sands.tv_sec - timer_now.tv_sec;
  else
    return 0;
}

/* Get new thread.  */
struct thread *
thread_get (struct thread_master *master, char type,
            int (*func) (struct thread *), void *arg)
{
  struct thread_master *m = master;
  struct thread *thread;

  if (m->unuse.head)
    thread = thread_trim_head (&m->unuse);
  else
    {
      thread = malloc (sizeof (struct thread));
      if (thread == NULL)
        return NULL;

      m->alloc++;
    }
  thread->type = type;
  thread->master = m;
  thread->func = func;
  thread->arg = arg;
//  thread->zg = zg;
  
  return thread;
}

/* Keep track of the maximum file descriptor for read/write. */
static void
thread_update_max_fd (struct thread_master *m, int fd)
{
  if (m && m->max_fd < fd)
    m->max_fd = fd;
}

/* Add new read thread. */
struct thread *
thread_add_read (struct thread_master *master,
		 int (*func) (struct thread *), void *arg, int fd)
{
  struct thread *thread;
  struct thread_master *m = master;

  assert (m != NULL);

  if (fd < 0)
    return NULL;

  thread = thread_get (master, THREAD_READ, func, arg);
  if (thread == NULL)
    return NULL;

  thread_update_max_fd (m, fd);
  PAL_SOCK_HANDLESET_SET (fd, &m->readfd);
  thread->u.fd = fd;
  thread_list_add (&m->read, thread);

  return thread;
}

/* Add new high priority read thread. */
struct thread *
thread_add_read_high (struct thread_master *master,
                 int (*func) (struct thread *), void *arg, int fd)
{
  struct thread_master *m = master;
  struct thread *thread;

  assert (m != NULL);

  if (fd < 0)
    return NULL;

  thread = thread_get (master, THREAD_READ_HIGH, func, arg);
  if (thread == NULL)
    return NULL;

  thread_update_max_fd (m, fd);
  PAL_SOCK_HANDLESET_SET (fd, &m->readfd);
  thread->u.fd = fd;
  thread_list_add (&m->read_high, thread);

  return thread;
}

/* Add new write thread. */
struct thread *
thread_add_write (struct thread_master *master,
                 int (*func) (struct thread *), void *arg, int fd)
{
  struct thread_master *m = master;
  struct thread *thread;

  assert (m != NULL);

  if (fd < 0 || PAL_SOCK_HANDLESET_ISSET (fd, &m->writefd))
    return NULL;

  thread = thread_get (m, THREAD_WRITE, func, arg);
  if (thread == NULL)
    return NULL;

  thread_update_max_fd (m, fd);
  PAL_SOCK_HANDLESET_SET (fd, &m->writefd);
  thread->u.fd = fd;
  thread_list_add (&m->write, thread);

  return thread;
}

static void
thread_add_timer_common (struct thread_master *m, struct thread *thread)
{
#ifndef TIMER_NO_SORT
  struct thread *tt;
#endif /* TIMER_NO_SORT */

  /* Set index.  */
  thread->index = m->index;

  /* Sort by timeval. */
#ifdef TIMER_NO_SORT
  thread_list_add (&m->timer[m->index], thread);
#else
  for (tt = m->timer[m->index].tail; tt; tt = tt->prev)
    if (timeval_cmp (thread->u.sands, tt->u.sands) >= 0)
      break;

  thread_list_add_after (&m->timer[m->index], tt, thread);
#endif /* TIMER_NO_SORT */

  /* Increment timer slot index.  */
  m->index++;
  m->index %= THREAD_TIMER_SLOT;
}

/* Add timer event thread. */
struct thread *
thread_add_timer (struct thread_master *master,
                 int (*func) (struct thread *), void *arg, long timer)
{
  struct thread_master *m = master;
  struct pal_timeval timer_now;
  struct thread *thread;

  assert (m != NULL);
  thread = thread_get (m, THREAD_TIMER, func, arg);
  if (thread == NULL)
    return NULL;

  /* Do we need jitter here? */
  pal_time_tzcurrent (&timer_now, NULL);
  timer_now.tv_sec += timer;
  thread->u.sands = timer_now;

  /* Common process.  */
  thread_add_timer_common (m, thread);

  return thread;
}

/* Add timer event thread. */
struct thread *
thread_add_timer_timeval (struct thread_master *master,
                          int (*func) (struct thread *), void *arg,
                          struct pal_timeval timer)
{
  struct thread_master *m = master;
  struct pal_timeval timer_now;
  struct thread *thread;

  assert (m != NULL);

  thread = thread_get (m, THREAD_TIMER, func, arg);
  if (thread == NULL)
    return NULL;

  /* Do we need jitter here? */
  pal_time_tzcurrent (&timer_now, NULL);
  timer_now.tv_sec += timer.tv_sec;
  timer_now.tv_usec += timer.tv_usec;
  while (timer_now.tv_usec >= TV_USEC_PER_SEC)
    {
      timer_now.tv_sec++;
      timer_now.tv_usec -= TV_USEC_PER_SEC;
    }

  /* Correct negative value.  */
  if (timer_now.tv_sec < 0)
    timer_now.tv_sec = PAL_TIME_MAX_TV_SEC;
  if (timer_now.tv_usec < 0)
    timer_now.tv_usec = PAL_TIME_MAX_TV_USEC;

  thread->u.sands = timer_now;

  /* Common process.  */
  thread_add_timer_common (m, thread);

  return thread;
}

/* Add simple event thread. */
struct thread *
thread_add_event (struct thread_master *master,
		  int (*func) (struct thread *), void *arg, int val)
{
  struct thread *thread;
  struct thread_master *m = master;

  assert (m != NULL);

  thread = thread_get (m, THREAD_EVENT, func, arg);
  if (thread == NULL)
    return NULL;

  thread->u.val = val;
  thread_list_add (&m->event, thread);

  return thread;
}

/* Add low priority event thread. */
struct thread *
thread_add_event_low (struct thread_master *master,
                      int (*func) (struct thread *), void *arg, int val)
{
  struct thread *thread;
  struct thread_master *m = master;

  assert (m != NULL);
 
  thread = thread_get (m, THREAD_EVENT_LOW, func, arg);
  if (thread == NULL)
    return NULL;

  thread->u.val = val;
  thread_list_add (&m->event_low, thread);

  return thread;
}

/* Add pending read thread. */
struct thread *
thread_add_read_pend (struct thread_master *master, 
		      int (*func) (struct thread *), void *arg, int val)
{
  struct thread *thread;
  struct thread_master *m = master;

  assert (m != NULL);
 
  thread = thread_get (m, THREAD_READ_PEND, func, arg);
  if (thread == NULL)
    return NULL;

  thread->u.val = val;
  thread_list_add (&m->read_pend, thread);

  return thread;
}

/* Cancel thread from scheduler. */
void
thread_cancel (struct thread *thread)
{
  switch (thread->type)
    {
    case THREAD_READ:
      PAL_SOCK_HANDLESET_CLR (thread->u.fd, &thread->master->readfd);
      thread_list_delete (&thread->master->read, thread);
      break;
    case THREAD_READ_HIGH:
      PAL_SOCK_HANDLESET_CLR (thread->u.fd, &thread->master->readfd);
      thread_list_delete (&thread->master->read_high, thread);
      break;
    case THREAD_WRITE:
      assert (PAL_SOCK_HANDLESET_ISSET (thread->u.fd, &thread->master->writefd));
      PAL_SOCK_HANDLESET_CLR (thread->u.fd, &thread->master->writefd);
      thread_list_delete (&thread->master->write, thread);
      break;
    case THREAD_TIMER:
      thread_list_delete (&thread->master->timer[(int)thread->index], thread);
      break;
    case THREAD_EVENT:
      thread_list_delete (&thread->master->event, thread);
      break;
    case THREAD_READ_PEND:
      thread_list_delete (&thread->master->read_pend, thread);
      break;
    case THREAD_EVENT_LOW:
      thread_list_delete (&thread->master->event_low, thread);
      break;
    case THREAD_QUEUE:
      switch (thread->priority)
	{
	case THREAD_PRIORITY_HIGH:
	  thread_list_delete (&thread->master->queue_high, thread);
	  break;
	case THREAD_PRIORITY_MIDDLE:
	  thread_list_delete (&thread->master->queue_middle, thread);
	  break;
	case THREAD_PRIORITY_LOW:
	  thread_list_delete (&thread->master->queue_low, thread);
	  break;
	}
      break;
    default:
      break;
    }
  thread->type = THREAD_UNUSED;
  thread_add_unuse (thread->master, thread);
}

/* Delete all events which has argument value arg. */
void
thread_cancel_event (struct thread_master *master, void *arg)
{
  struct thread_master *m = master;
  struct thread *thread;
  struct thread *t;

  thread = m->event.head;
  while (thread)
    {
      t = thread;
      thread = t->next;

      if (t->arg == arg)
	{
	  thread_list_delete (&m->event, t);
	  t->type = THREAD_UNUSED;
	  thread_add_unuse (m, t);
	}
    }

  /* Since Event could have been Queued search queue_high */
  thread = m->queue_high.head;
  while (thread)
    {
      t = thread;
      thread = t->next;

      if (t->arg == arg)
        {
          thread_list_delete (&m->queue_high, t);
          t->type = THREAD_UNUSED;
          thread_add_unuse (m, t);
        }
    }

  return;
}

/* Delete all low-events which has argument value arg */
void
thread_cancel_event_low (struct thread_master *master, void *arg)
{
  struct thread_master *m = master;
  struct thread *thread;
  struct thread *t;

  thread = m->event_low.head;
  while (thread)
    {
      t = thread;
      thread = t->next;

      if (t->arg == arg)
        {
          thread_list_delete (&m->event_low, t);
          t->type = THREAD_UNUSED;
          thread_add_unuse (m, t);
        }
    }

  /* Since Event could have been Queued search queue_low */
  thread = m->queue_low.head;
  while (thread)
    {
      t = thread;
      thread = t->next;

      if (t->arg == arg)
        {
          thread_list_delete (&m->queue_low, t);
          t->type = THREAD_UNUSED;
          thread_add_unuse (m, t);
        }
    }

  return;
}

#ifdef RTOS_DEFAULT_WAIT_TIME
/* Delete all read events which has argument value arg. */
void
thread_cancel_read (struct thread_master *master, void *arg)
{
  struct thread_master *m = master;
  struct thread *thread;

  thread = m->read.head;
  while (thread)
    {
      struct thread *t;

      t = thread;
      thread = t->next;

      if (t->arg == arg)
	{
	  thread_list_delete (&m->read, t);
	  t->type = THREAD_UNUSED;
	  thread_add_unuse (m, t);
	}
    }
}

/* Delete all write events which has argument value arg. */
void
thread_cancel_write (struct thread_master *master, void *arg)
{
  struct thread_master *m = master;
  struct thread *thread;

  thread = m->write.head;
  while (thread)
    {
      struct thread *t;

      t = thread;
      thread = t->next;

      if (t->arg == arg)
	{
	  thread_list_delete (&m->write, t);
	  t->type = THREAD_UNUSED;
	  thread_add_unuse (m, t);
	}
    }
}

/* Delete all timer events which has argument value arg. */
void
thread_cancel_timer (struct thread_master *master, void *arg)
{
  struct thread_master *m = master;
  struct thread *thread;
  int i;
  
  for (i = 0; i < THREAD_TIMER_SLOT; i++)
    {
      thread = m->timer[i].head;
      while (thread)
	{
	  struct thread *t;
	  
	  t = thread;
	  thread = t->next;
	  
	  if (t->arg == arg)
	    {
	      thread_list_delete (&m->timer[i], t);
	      t->type = THREAD_UNUSED;
	      thread_add_unuse (m, t);
	    }
	}
    }
}

struct pal_timeval *
thread_timer_wait (struct thread_master *m, struct pal_timeval *timer_val)
{
  timer_val->tv_sec = 1;
  timer_val->tv_usec = 0;
  return timer_val;
}
#else /* ! RTOS_DEFAULT_WAIT_TIME */
#ifdef HAVE_RTOS_TIMER
struct pal_timeval *
thread_timer_wait (struct thread_master *m, struct pal_timeval *timer_val)
{
  rtos_set_time (timer_val);
  return timer_val;
}
#else /* ! HAVE_RTOS_TIMER */
#ifdef HAVE_RTOS_TIC
struct pal_timeval *
thread_timer_wait (struct thread_master *m, struct pal_timeval *timer_val)
{
  timer_val->tv_sec = 0;
  timer_val->tv_usec = 10;
  return timer_val;
}
#else /* ! HAVE_RTOS_TIC */
#ifdef TIMER_NO_SORT
struct pal_timeval *
thread_timer_wait (struct thread_master *m, struct pal_timeval *timer_val)
{
  struct pal_timeval timer_now;
  struct pal_timeval timer_min;
  struct pal_timeval *timer_wait;
  struct thread *thread;
  int i;

  timer_wait = NULL;

  for (i = 0; i < THREAD_TIMER_SLOT; i++)
    for (thread = m->timer[i].head; thread; thread = thread->next)
      {
	if (! timer_wait)
	  timer_wait = &thread->u.sands;
	else if (timeval_cmp (thread->u.sands, *timer_wait) < 0)
	  timer_wait = &thread->u.sands;
      }

  if (timer_wait)
    {
      timer_min = *timer_wait;

      pal_time_tzcurrent (&timer_now, NULL);
      timer_min = timeval_subtract (timer_min, timer_now);

      if (timer_min.tv_sec < 0)
	{
	  timer_min.tv_sec = 0;
	  timer_min.tv_usec = 10;
	}

      *timer_val = timer_min;
      return timer_val;
    }
  return NULL;
}
#else /* ! TIMER_NO_SORT */
/* Pick up smallest timer.  */
struct pal_timeval *
thread_timer_wait (struct thread_master *m, struct pal_timeval *timer_val)
{
  struct pal_timeval timer_now;
  struct pal_timeval timer_min;
  struct pal_timeval *timer_wait;
  struct thread *thread;
  int i;

  timer_wait = NULL;

  for (i = 0; i < THREAD_TIMER_SLOT; i++)
    if ((thread = m->timer[i].head) != NULL)
      {
	if (! timer_wait)
	  timer_wait = &thread->u.sands;
	else if (timeval_cmp (thread->u.sands, *timer_wait) < 0)
	  timer_wait = &thread->u.sands;
      }

  if (timer_wait)
    {
      timer_min = *timer_wait;

      pal_time_tzcurrent (&timer_now, NULL);
      timer_min = timeval_subtract (timer_min, timer_now);

      if (timer_min.tv_sec < 0)
	{
	  timer_min.tv_sec = 0;
	  timer_min.tv_usec = 10;
	}

      *timer_val = timer_min;
      return timer_val;
    }
  return NULL;
}
#endif /* TIMER_NO_SORT */
#endif /* HAVE_RTOS_TIC */
#endif /* HAVE_RTOS_TIMER */
#endif /* RTOS_DEFAULT_WAIT_TIME */

struct thread *
thread_run (struct thread_master *m, struct thread *thread,
	    struct thread *fetch)
{
  *fetch = *thread;
  thread->type = THREAD_UNUSED;
  thread_add_unuse (m, thread);
  return fetch;
}

void
thread_enqueue_high (struct thread_master *m, struct thread *thread)
{
  thread->type = THREAD_QUEUE;
  thread->priority = THREAD_PRIORITY_HIGH;
  thread_list_add (&m->queue_high, thread);
}

void
thread_enqueue_middle (struct thread_master *m, struct thread *thread)
{
  thread->type = THREAD_QUEUE;
  thread->priority = THREAD_PRIORITY_MIDDLE;
  thread_list_add (&m->queue_middle, thread);
}

void
thread_enqueue_low (struct thread_master *m, struct thread *thread)
{
  thread->type = THREAD_QUEUE;
  thread->priority = THREAD_PRIORITY_LOW;
  thread_list_add (&m->queue_low, thread);
}

/* When the file is ready move to queueu.  */
int
thread_process_fd (struct thread_master *m, struct thread_list *list,
		   pal_sock_set_t *fdset, pal_sock_set_t *mfdset)
{
  struct thread *thread;
  struct thread *next;
  int ready = 0;

  for (thread = list->head; thread; thread = next)
    {
      next = thread->next;

      if (PAL_SOCK_HANDLESET_ISSET (THREAD_FD (thread), fdset))
	{
	  PAL_SOCK_HANDLESET_CLR(THREAD_FD (thread), mfdset);
	  thread_list_delete (list, thread);
	  thread_enqueue_middle (m, thread);
	  ready++;
	}
    }
  return ready;
}
/* Fetch next ready thread. */
struct thread *
thread_fetch_return (struct thread_master *master, struct thread *fetch)
{
  struct thread_master *m = master;
  int num;
  struct thread *thread;
  struct thread *next;
  fd_set readfd;
  fd_set writefd;
  fd_set exceptfd;
  struct pal_timeval timer_now;
  struct pal_timeval timer_val;
  struct pal_timeval *timer_wait;
  struct pal_timeval timer_nowait;
  int i;


  timer_nowait.tv_sec = 0;
  timer_nowait.tv_usec = 0;


      /* Pending read is exception. */
      if ((thread = thread_trim_head (&m->read_pend)) != NULL)
		return thread_run (m, thread, fetch);

      /* Check ready queue.  */
      if ((thread = thread_trim_head (&m->queue_high)) != NULL)
		return thread_run (m, thread, fetch);

      if ((thread = thread_trim_head (&m->queue_middle)) != NULL)
	return thread_run (m, thread, fetch);

      if ((thread = thread_trim_head (&m->queue_low)) != NULL)
	return thread_run (m, thread, fetch);

      /* Check all of available events.  */
      /* Check events.  */
      while ((thread = thread_trim_head (&m->event)) != NULL)
	thread_enqueue_high (m, thread);

      /* Check timer.  */
      pal_time_tzcurrent (&timer_now, NULL);

      for (i = 0; i < THREAD_TIMER_SLOT; i++)
	for (thread = m->timer[i].head; thread; thread = next)
	  {
	    next = thread->next;
	    if (timeval_cmp (timer_now, thread->u.sands) >= 0)
	      {
		thread_list_delete (&m->timer[i], thread);
		thread_enqueue_middle (m, thread);
	      }
#ifndef TIMER_NO_SORT
	    else
	      break;
#endif /* TIMER_NO_SORT */
	  }

    /* Structure copy.  */
      readfd = m->readfd;
      writefd = m->writefd;
      exceptfd = m->exceptfd;

      /* Check any thing to be execute.  */
      if (m->queue_high.head || m->queue_middle.head || m->queue_low.head)
	timer_wait = &timer_nowait;
      else
	timer_wait = thread_timer_wait (m, &timer_val);

	timer_wait = &timer_nowait;
        /* First check for sockets.  Return immediately.  */
      num = select (m->max_fd + 1, &readfd, &writefd, &exceptfd,
			     timer_wait);



      /* Error handling.  */
      if (num < 0)
	{
	  return NULL;
	}


      /* File descriptor is readable/writable.  */
      if (num > 0)
	{
	  /* High priority read thead. */
	  thread_process_fd (m, &m->read_high, &readfd, &m->readfd);

	  /* Normal priority read thead. */
	  thread_process_fd (m, &m->read, &readfd, &m->readfd);

	  /* Write thead. */
	  thread_process_fd (m, &m->write, &writefd, &m->writefd);
	}



      /* Low priority events. */
      if ((thread = thread_trim_head (&m->event_low)) != NULL)
        thread_enqueue_low (m, thread);

	return NULL;
}


/* Fetch next ready thread. */
struct thread *
thread_fetch (struct thread_master *master, struct thread *fetch)
{
  struct thread_master *m = master;
  int num;
  struct thread *thread;
  struct thread *next;
  pal_sock_set_t readfd;
  pal_sock_set_t writefd;
  pal_sock_set_t exceptfd;
  struct pal_timeval timer_now;
  struct pal_timeval timer_val;
  struct pal_timeval *timer_wait;
  struct pal_timeval timer_nowait;
  int i;

#ifdef RTOS_DEFAULT_WAIT_TIME 
  /* 1 sec might not be optimized */
  timer_nowait.tv_sec = 1;
  timer_nowait.tv_usec = 0;
#else
  timer_nowait.tv_sec = 0;
  timer_nowait.tv_usec = 0;
#endif /* RTOS_DEFAULT_WAIT_TIME */

  while (1)
    {
      /* Pending read is exception. */
      if ((thread = thread_trim_head (&m->read_pend)) != NULL)
	return thread_run (m, thread, fetch);

      /* Check ready queue.  */
      if ((thread = thread_trim_head (&m->queue_high)) != NULL)
	return thread_run (m, thread, fetch);

      if ((thread = thread_trim_head (&m->queue_middle)) != NULL)
	return thread_run (m, thread, fetch);

      if ((thread = thread_trim_head (&m->queue_low)) != NULL)
	return thread_run (m, thread, fetch);

      /* Check all of available events.  */

      /* Check events.  */
      while ((thread = thread_trim_head (&m->event)) != NULL)
	thread_enqueue_high (m, thread);

      /* Check timer.  */
      pal_time_tzcurrent (&timer_now, NULL);

      for (i = 0; i < THREAD_TIMER_SLOT; i++)
	for (thread = m->timer[i].head; thread; thread = next)
	  {
	    next = thread->next;
	    if (timeval_cmp (timer_now, thread->u.sands) >= 0)
	      {
		thread_list_delete (&m->timer[i], thread);
		thread_enqueue_middle (m, thread);
	      }
#ifndef TIMER_NO_SORT
	    else
	      break;
#endif /* TIMER_NO_SORT */
	  }
      
      /* Structure copy.  */
      readfd = m->readfd;
      writefd = m->writefd;
      exceptfd = m->exceptfd;

      /* Check any thing to be execute.  */
      if (m->queue_high.head || m->queue_middle.head || m->queue_low.head)
	timer_wait = &timer_nowait;
      else
	timer_wait = thread_timer_wait (m, &timer_val);
  
      /* First check for sockets.  Return immediately.  */
      num = select (m->max_fd + 1, &readfd, &writefd, &exceptfd,
			     timer_wait);

      /* Error handling.  */
      if (num < 0)
	{
	  if (errno == EINTR)
	    continue;
	  if (errno == EBADF){
	  	fprintf(stderr, "ERROR:%s:%d THREAD FD ALREADY COLSED\n",__FUNCTION__,__LINE__);
	  	return NULL;
	  }
	  return NULL;
	}

      /* File descriptor is readable/writable.  */
      if (num > 0)
	{
	  /* High priority read thead. */
	  thread_process_fd (m, &m->read_high, &readfd, &m->readfd);

	  /* Normal priority read thead. */
	  thread_process_fd (m, &m->read, &readfd, &m->readfd);

	  /* Write thead. */
	  thread_process_fd (m, &m->write, &writefd, &m->writefd);
	}

      /* Low priority events. */
      if ((thread = thread_trim_head (&m->event_low)) != NULL)
        thread_enqueue_low (m, thread);
    }
}

/* Call the thread.  */
void
thread_call (struct thread *thread)
{
  (*thread->func) (thread);
}

/* Fake execution of the thread with given arguemment.  */
struct thread *
thread_execute (struct thread_master *master,
                int (*func)(struct thread *), 
                void *arg,
                int val)
{
  struct thread dummy; 

  pal_mem_set (&dummy, 0, sizeof (struct thread));

  dummy.type = THREAD_EVENT;
  dummy.master = NULL;
  dummy.func = func;
  dummy.arg = arg;
  dummy.u.val = val;
  thread_call (&dummy);

  return NULL;
}

/* Real time OS support routine.  */
#ifdef HAVE_RTOS_TIC
#ifdef RTOS_EXECUTE_ONE_THREAD
int
lib_tic (struct thread_master *master, struct thread *thread)
{
  if (thread_fetch (master, thread))
    {
      thread_call(thread);
      /* To indicate that a thread has run.  */
      return(1);
    }
  /* To indicate that no thread has run yet.  */
  return (0);  
}
#else /* ! RTOS_EXECUTE_ONE_THREAD */
int
lib_tic (struct thread_master *master, struct thread *thread)
{
  while (thread_fetch (master, thread))
    thread_call(thread);
  return(0);
}
#endif /* ! RTOS_EXECUTE_ONE_THREAD */
#endif /* HAVE_RTOS_TIC */
