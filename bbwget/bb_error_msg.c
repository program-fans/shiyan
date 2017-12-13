#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "libbb.h"

void bb_verror_msg(const char *s, va_list p)
{
	fflush(stdout);
	fprintf(stderr, "%s: ", bb_applet_name);
	vfprintf(stderr, s, p);
}

void bb_vperror_msg(const char *s, va_list p)
{
	int err=errno;
	if(s == 0) s = "";
	bb_verror_msg(s, p);
	if (*s) s = ": ";
	fprintf(stderr, "%s%s\n", s, strerror(err));
}

#include <netdb.h>
void bb_vherror_msg(const char *s, va_list p)
{
	if(s == 0)
		s = "";
	bb_verror_msg(s, p);
	if (*s)
		fputs(": ", stderr);
	herror("");
}

#ifdef LIB_BBWGET_FOR_THREAD
void bb_thread_exit(int code)
{
	pthread_exit(&code);
}
#endif

void bb_herror_msg_and_die(const char *s, ...)
{
	va_list p;

	va_start(p, s);
	bb_vherror_msg(s, p);
	va_end(p);
	exit(bb_default_error_retval);
}

void bb_error_msg_and_die(const char *s, ...)
{
	va_list p;

	va_start(p, s);
	bb_verror_msg(s, p);
	va_end(p);
	putc('\n', stderr);
	exit(bb_default_error_retval);
}

void bb_perror_msg_and_die(const char *s, ...)
{
	va_list p;

	va_start(p, s);
	bb_vperror_msg(s, p);
	va_end(p);
	exit(bb_default_error_retval);
}

