/* vi: set sw=4 ts=4: */
/*
 * Busybox main internal header file
 *
 * Licensed under the GPL v2 or later, see the file LICENSE in this tarball.
 *
 * Based in part on code from sash, Copyright (c) 1999 by David I. Bell
 * Permission has been granted to redistribute this code under the GPL.
 *
 */
#ifndef	__LIBBUSYBOX_H__
#define	__LIBBUSYBOX_H__    1

// =================== config
#define BB_STR 1
#define ENABLE_FEATURE_CLEAN_UP 0
// =================== config -- end

#include <stdio.h>
#include <stdarg.h>

/* Some useful definitions */
#define FALSE   ((int) 0)
#define TRUE    ((int) 1)
#define SKIP	((int) 2)

#ifndef MIN
#define	MIN(a,b) (((a)<(b))?(a):(b))
#endif

#ifndef MAX
#define	MAX(a,b) (((a)>(b))?(a):(b))
#endif

#ifdef LIB_BBWGET_FOR_THREAD
#include <pthread.h>
extern void bb_thread_exit(int code);
#define exit(code) bb_thread_exit(code);
#endif

#define bb_default_error_retval EXIT_FAILURE

extern const char *bb_applet_name;
extern void bb_verror_msg(const char *s, va_list p);
extern void bb_vperror_msg(const char *s, va_list p);
extern void bb_vherror_msg(const char *s, va_list p);
extern void bb_herror_msg_and_die(const char *s, ...);
extern void bb_error_msg_and_die(const char *s, ...);
extern void bb_perror_msg_and_die(const char *s, ...);

void bb_show_usage();

#ifdef XMALLOC
/* dmalloc will redefine these to it's own implementation. It is safe
 * to have the prototypes here unconditionally.  */
extern void *xmalloc(size_t size);
extern void *xrealloc(void *old, size_t size);
extern void *xcalloc(size_t nmemb, size_t size);
#else
#define xmalloc malloc
#define xrealloc realloc
#define xcalloc calloc
#endif

extern char *safe_strncpy(char *dst, const char *src, size_t size);
extern int safe_strtol(char *arg, long* value);
extern int safe_strtoi(char *arg, int* value);
extern int safe_strtod(char *arg, double* value);
extern int safe_strtoul(char *arg, unsigned long* value);

#ifdef BB_STR
extern char *bb_xstrdup (const char *s);
extern char *bb_xstrndup (const char *s, int n);
#endif


#ifdef X_OPEN
extern FILE *bb_xfopen(const char *path, const char *mode);
extern int bb_xopen(const char *pathname, int flags);
extern ssize_t bb_xread(int fd, void *buf, size_t count);
#else
#define bb_xfopen fopen
#define bb_xopen(pathname, flags) open(pathname, flags, 0777)
#define bb_xread read
#endif
extern void bb_xread_all(int fd, void *buf, size_t count);
extern unsigned char bb_xread_char(int fd);

extern char *bb_xasprintf(const char *format, ...);



#define BB_GETOPT_ERROR 0x80000000UL
extern const char *bb_opt_complementally;
extern const struct option *bb_applet_long_options;
extern unsigned long bb_getopt_ulflags(int argc, char **argv, const char *applet_opts, ...);


typedef struct llist_s {
	char *data;
	struct llist_s *link;
} llist_t;
extern llist_t *llist_add_to(llist_t *old_head, char *new_item);
extern llist_t *llist_add_to_end(llist_t *list_head, char *data);
extern llist_t *llist_free_one(llist_t *elm);
extern void llist_free(llist_t *elm);

#include <netinet/in.h>
extern unsigned short bb_lookup_port(const char *port, const char *protocol, unsigned short default_port);
extern void bb_lookup_host(struct sockaddr_in *s_in, const char *host);
extern int xconnect(struct sockaddr_in *s_addr);

#endif

