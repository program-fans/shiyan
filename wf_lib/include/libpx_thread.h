/* Copyright (C) 2001-2003 IP Infusion, Inc. All Rights Reserved. */

#ifndef _LIBPX_THREAD_H
#define _LIBPX_THREAD_H

#include "pal_time.h"

/* Linked list of thread. */
struct thread_list
{
	struct thread *head;
	struct thread *tail;
	unsigned int count;
};

/* Master of the theads. */
struct thread_master
{
	/* Priority based queue.  */
	struct thread_list queue_high;
	struct thread_list queue_middle;
	struct thread_list queue_low;

	/* Timer */
#define THREAD_TIMER_SLOT           4
	int index;
	struct thread_list timer[THREAD_TIMER_SLOT];

	/* Thread to be executed.  */
	struct thread_list read_pend;
	struct thread_list read_high;
	struct thread_list read;
	struct thread_list write;
	struct thread_list event;
	struct thread_list event_low;
	struct thread_list unuse;
	fd_set readfd;
	fd_set writefd;
	fd_set exceptfd;
	int max_fd;
	unsigned int alloc;
};

/* Thread structure. */
struct thread
{
	/* Linked list.  */
	struct thread *next;
	struct thread *prev;

	/* Pointer to the struct thread_master.  */
	struct thread_master *master;

	/* Pointer to the struct lib_globals. */
	struct lib_globals *zg;

	/* Event function.  */
	int (*func) (struct thread *);

	/* Event argument.  */
	void *arg;

	/* Thread type.  */
	char type;

	/* Priority.  */
	char priority;
#define THREAD_PRIORITY_HIGH         0
#define THREAD_PRIORITY_MIDDLE       1
#define THREAD_PRIORITY_LOW          2

	/* Thread timer index.  */
	char index;

	/* Arguments.  */
	union 
	{
		/* Second argument of the event.  */
		int val;

		/* File descriptor in case of read/write.  */
		int fd;

		/* Rest of time sands value.  */
		struct pal_timeval sands;
	} u;
};

/* Thread types.  */
#define THREAD_READ             0
#define THREAD_WRITE            1
#define THREAD_TIMER            2
#define THREAD_EVENT            3
#define THREAD_QUEUE            4
#define THREAD_UNUSED           5
#define THREAD_READ_HIGH        6
#define THREAD_READ_PEND        7
#define THREAD_EVENT_LOW        8

/* Macros.  */
#define THREAD_ARG(X)           ((X)->arg)
#define THREAD_FD(X)            ((X)->u.fd)
#define THREAD_VAL(X)           ((X)->u.val)
#define THREAD_TIME_VAL(X)      ((X)->u.sands)
#define THREAD_GLOB(X)          ((X)->zg)

#define THREAD_READ_ON(global,thread,func,arg,sock) \
  do { \
    if (! thread) \
      thread = thread_add_read (global, func, arg, sock); \
  } while (0)

#define THREAD_WRITE_ON(global,thread,func,arg,sock) \
  do { \
    if (! thread) \
      thread = thread_add_write (global, func, arg, sock); \
  } while (0)

#define THREAD_TIMER_ON(global,thread,func,arg,time) \
  do { \
    if (! thread) \
      thread = thread_add_timer (global, func, arg, time); \
  } while (0)

#define THREAD_OFF(thread) \
  do { \
    if (thread) \
      { \
        thread_cancel (thread); \
        thread = NULL; \
      } \
  } while (0)

#define THREAD_READ_OFF(thread)   THREAD_OFF(thread)
#define THREAD_WRITE_OFF(thread)  THREAD_OFF(thread)
#define THREAD_TIMER_OFF(thread)  THREAD_OFF(thread)

/* Prototypes.  */
extern struct thread_master *thread_master_create ();
extern void thread_master_finish (struct thread_master *);

extern void thread_list_add (struct thread_list *, struct thread *);
extern void thread_list_execute (struct thread_master *, struct thread_list *);
extern void thread_list_clear (struct thread_master  *, struct thread_list *);

extern struct thread *thread_get (struct thread_master  *, char,
			   int (*) (struct thread *), void *);

extern struct thread *thread_add_read (struct thread_master *, int (*)(struct thread *), void *, int);

extern struct thread *thread_add_read_high (struct thread_master *,
                                     int (*)(struct thread *), void *,
				     int);
extern struct thread *thread_add_write (struct thread_master *,
                                 int (*)(struct thread *), void *,
				 int);
extern struct thread *thread_add_timer (struct thread_master *,
                                 int (*)(struct thread *), void *, long);
extern struct thread *thread_add_timer_timeval (struct thread_master *,
					 int (*)(struct thread *),
					 void *, struct pal_timeval);
extern struct thread *thread_add_event (struct thread_master *,
                                 int (*)(struct thread *), void *,
				 int);
extern struct thread *thread_add_event_low (struct thread_master *,
				     int (*)(struct thread *), void *,
				     int);
extern struct thread *thread_add_read_pend (struct thread_master *zg, int (*func) (struct thread *), void *arg, int val);
extern void thread_cancel (struct thread *);
extern void thread_cancel_event (struct thread_master *, void *);
extern void thread_cancel_event_low (struct thread_master *, void *);
extern void thread_cancel_timer (struct thread_master *, void *);
extern void thread_cancel_write (struct thread_master *, void *);
extern void thread_cancel_read (struct thread_master *, void *);
extern struct thread *thread_fetch (struct thread_master *, struct thread *);
extern struct thread *thread_execute (struct thread_master *, int (*)(struct thread *), void *, int);
extern void thread_call (struct thread *);
extern unsigned int thread_timer_remain_second (struct thread *);

#endif /* _ZEBOS_THREAD_H */
