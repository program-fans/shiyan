#ifndef SELECT_EVENT_H_
#define SELECT_EVENT_H_ 1

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

/* Flags */
#define EVENT_FLAG_READABLE 1
#define EVENT_FLAG_WRITEABLE 2
#define EVENT_FLAG_WRITABLE EVENT_FLAG_WRITEABLE

/* This is strictly a timer event */
#define EVENT_FLAG_TIMER 4

/* This is a read or write event with an associated timeout */
#define EVENT_FLAG_TIMEOUT 8

#define EVENT_TIMER_BITS (EVENT_FLAG_TIMER | EVENT_FLAG_TIMEOUT)

/* Private flags */
#define EVENT_FLAG_DELETED 256

/* Callback function */
typedef int (*EventCallbackFunc)(void *e,int fd,unsigned int flags,void *data);

/* Handler structure */
typedef struct EventHandler_t {
    struct EventHandler_t *next; /* Link in list                           */
    int fd;			/* File descriptor for select              */
    unsigned int flags;		/* Select on read or write; enable timeout */
    struct timeval tmout;	/* Absolute time for timeout               */
    EventCallbackFunc fn;	/* Callback function                       */
    void *data;			/* Extra data to pass to callback          */
} EventHandler;

/* Selector structure */
typedef struct EventSelector_t {
    EventHandler *handlers;	/* Linked list of EventHandlers            */
    int nestLevel;		/* Event-handling nesting level            */
    int opsPending;		/* True if operations are pending          */
    int destroyPending;		/* If true, a destroy is pending           */
} EventSelector;

/* Create an event selector */
extern EventSelector *Event_CreateSelector(void);

/* Destroy the event selector */
extern void Event_DestroySelector(EventSelector *es);

/* Handle one event */
extern int Event_HandleEvent(EventSelector *es);

/* Add a handler for a ready file descriptor */
extern EventHandler *Event_AddHandler(EventSelector *es,
				      int fd,
				      unsigned int flags,
				      EventCallbackFunc fn, void *data);

/* Add a handler for a ready file descriptor with associated timeout*/
extern EventHandler *Event_AddHandlerWithTimeout(EventSelector *es,
						 int fd,
						 unsigned int flags,
						 struct timeval t,
						 EventCallbackFunc fn,
						 void *data);


/* Add a timer handler */
extern EventHandler *Event_AddTimerHandler(EventSelector *es,
					   struct timeval t,
					   EventCallbackFunc fn,
					   void *data);

/* Change the timeout of a timer handler */
void Event_ChangeTimeout(EventHandler *handler, struct timeval t);

/* Delete a handler */
extern int Event_DelHandler(EventSelector *es,
			    EventHandler *eh);

/* Retrieve callback function from a handler */
extern EventCallbackFunc Event_GetCallback(EventHandler *eh);

/* Retrieve data field from a handler */
extern void *Event_GetData(EventHandler *eh);

/* Set callback and data to new values */
extern void Event_SetCallbackAndData(EventHandler *eh,
				     EventCallbackFunc fn,
				     void *data);

/* Handle a signal synchronously in event loop */
int Event_HandleSignal(EventSelector *es, int sig, void (*handler)(int sig));

/* Reap children synchronously in event loop */
int Event_HandleChildExit(EventSelector *es, pid_t pid,
			  void (*handler)(pid_t, int, void *), void *data);


#endif
