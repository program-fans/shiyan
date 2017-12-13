/* vi: set sw=4 ts=4: */
/*
 * Utility routines.
 *
 * Copyright (C) 1999-2004 by Erik Andersen <andersen@codepoet.org>
 *
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

/* Since gcc always inlines strlen(), this saves a byte or two, but we need
 * the #undef here to avoid endless loop from #define strlen bb_strlen */
#ifdef L_strlen
#define BB_STRLEN_IMPLEMENTATION
#endif

#include "libbb.h"

const char * const bb_msg_memory_exhausted = "memory exhausted";

#ifdef XMALLOC
void *xmalloc(size_t size)
{
	void *ptr = malloc(size);
	if (ptr == NULL && size != 0)
		bb_error_msg_and_die(bb_msg_memory_exhausted);
	return ptr;
}

void *xrealloc(void *ptr, size_t size)
{
	ptr = realloc(ptr, size);
	if (ptr == NULL && size != 0)
		bb_error_msg_and_die(bb_msg_memory_exhausted);
	return ptr;
}

void *xcalloc(size_t nmemb, size_t size)
{
	void *ptr = calloc(nmemb, size);
	if (ptr == NULL && nmemb != 0 && size != 0)
		bb_error_msg_and_die(bb_msg_memory_exhausted);
	return ptr;
}
#endif /* DMALLOC */


/* Like strncpy but make sure the resulting string is always 0 terminated. */
char * safe_strncpy(char *dst, const char *src, size_t size)
{
	dst[size-1] = '\0';
	return strncpy(dst, src, size-1);
}

#include <assert.h>
int safe_strtol(char *arg, long* value)
{
	char *endptr;
	int errno_save = errno;

	assert(arg!=NULL);
	errno = 0;
	*value = strtol(arg, &endptr, 0);
	if (errno != 0 || *endptr!='\0' || endptr==arg) {
		return 1;
	}
	errno = errno_save;
	return 0;
}

int safe_strtoi(char *arg, int* value)
{
	int error;
	long lvalue = *value;
	error = safe_strtol(arg, &lvalue);
	*value = (int) lvalue;
	return error;
}

int safe_strtod(char *arg, double* value)
{
	char *endptr;
	int errno_save = errno;

	assert(arg!=NULL);
	errno = 0;
	*value = strtod(arg, &endptr);
	if (errno != 0 || *endptr!='\0' || endptr==arg) {
		return 1;
	}
	errno = errno_save;
	return 0;
}

int safe_strtoul(char *arg, unsigned long* value)
{
	char *endptr;
	int errno_save = errno;

	assert(arg!=NULL);
	errno = 0;
	*value = strtoul(arg, &endptr, 0);
	if (errno != 0 || *endptr!='\0' || endptr==arg) {
		return 1;
	}
	errno = errno_save;
	return 0;
}



#ifdef BB_STR
char * bb_xstrdup (const char *s)
{
	char *t;

	if (s == NULL)
		return NULL;

	t = strdup (s);

	if (t == NULL)
		bb_error_msg_and_die(bb_msg_memory_exhausted);

	return t;
}

char * bb_xstrndup (const char *s, int n)
{
	char *t;

	if (s == NULL)
		bb_error_msg_and_die("bb_xstrndup bug");

	t = xmalloc(++n);

	return safe_strncpy(t,s,n);
}
#endif

#ifdef X_OPEN
FILE *bb_xfopen(const char *path, const char *mode)
{
	FILE *fp;
	if ((fp = fopen(path, mode)) == NULL)
		bb_perror_msg_and_die("%s", path);
	return fp;
}

int bb_xopen(const char *pathname, int flags)
{
	int ret;

	ret = open(pathname, flags, 0777);
	if (ret == -1) {
		bb_perror_msg_and_die("%s", pathname);
	}
	return ret;
}

ssize_t bb_xread(int fd, void *buf, size_t count)
{
	ssize_t size;

	size = read(fd, buf, count);
	if (size == -1) {
		bb_perror_msg_and_die(bb_msg_read_error);
	}
	return(size);
}
#endif

void bb_xread_all(int fd, void *buf, size_t count)
{
	ssize_t size;

	while (count) {
		if ((size = bb_xread(fd, buf, count)) == 0) {	/* EOF */
			bb_error_msg_and_die("Short read");
		}
		count -= size;
		buf = ((char *) buf) + size;
	}
	return;
}

unsigned char bb_xread_char(int fd)
{
	char tmp;

	bb_xread_all(fd, &tmp, 1);

	return(tmp);
}

#ifdef L_xferror
void bb_xferror(FILE *fp, const char *fn)
{
	if (ferror(fp)) {
		bb_error_msg_and_die("%s", fn);
	}
}
#endif

#ifdef L_xferror_stdout
void bb_xferror_stdout(void)
{
	bb_xferror(stdout, bb_msg_standard_output);
}
#endif

#ifdef L_xfflush_stdout
void bb_xfflush_stdout(void)
{
	if (fflush(stdout)) {
		bb_perror_msg_and_die(bb_msg_standard_output);
	}
}
#endif


char *bb_xasprintf(const char *format, ...)
{
	va_list p;
	int r;
	char *string_ptr;

#ifdef vasprintf
	va_start(p, format);
	r = vasprintf(&string_ptr, format, p);
	va_end(p);
#else
	va_start(p, format);
	r = vsnprintf(NULL, 0, format, p);
	va_end(p);
	string_ptr = xmalloc(r+1);
	va_start(p, format);
	r = vsnprintf(string_ptr, r+1, format, p);
	va_end(p);
#endif

	if (r < 0) {
		bb_perror_msg_and_die("bb_xasprintf");
	}
	return string_ptr;
}


/* END CODE */
/*
Local Variables:
c-file-style: "linux"
c-basic-offset: 4
tab-width: 4
End:
*/
