/*
 * ghttp.h -- A public interface to common http functions
 * Created: Christopher Blizzard <blizzard@appliedtheory.com>, 21-Aug-1998
 *
 * Copyright (C) 1998 Free Software Foundation
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef GHTTP_H
#define GHTTP_H

#include "ghttp_constants.h"
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _ghttp_request ghttp_request;

typedef enum ghttp_type_tag
{
  ghttp_type_get = 0,
  ghttp_type_options,
  ghttp_type_head,
  ghttp_type_post,
  ghttp_type_put,
  ghttp_type_delete,
  ghttp_type_trace,
  ghttp_type_connect,
  ghttp_type_propfind,
  ghttp_type_proppatch,
  ghttp_type_mkcol,
  ghttp_type_copy,
  ghttp_type_move,
  ghttp_type_lock,
  ghttp_type_unlock
} ghttp_type;

typedef enum ghttp_sync_mode_tag
{
  ghttp_sync = 0,
  ghttp_async
} ghttp_sync_mode;

typedef enum ghttp_status_tag
{
  ghttp_error = -1,
  ghttp_not_done,
  ghttp_next,		// for post, need to set body that left 
  ghttp_done
} ghttp_status;

typedef enum ghttp_proc_tag
{
  ghttp_proc_none = 0,
  ghttp_proc_request,
  ghttp_proc_response_hdrs,
  ghttp_proc_response,
  ghttp_proc_done
} ghttp_proc;

typedef struct ghttp_current_status_tag
{
  ghttp_proc         proc;        /* what's it doing? */
  int                bytes_read;  /* how many bytes have been read? */
  int                bytes_total; /* how many total */
} ghttp_current_status;

/* create a new request object */
extern ghttp_request *ghttp_request_new(void);
extern ghttp_request *ghttp_request_new2(ghttp_type action, char *url, ghttp_sync_mode mode);
extern ghttp_request *ghttp_request_new_url(char *url);

/* delete a current request object */
extern void ghttp_request_destroy(ghttp_request *a_request);

/* Validate a uri
 * This will return -1 if a uri is invalid
 */
extern int ghttp_uri_validate(char *a_uri);

/* Set a uri in a request
 * This will return -1 if the uri is invalid
 */

extern int ghttp_set_uri(ghttp_request *a_request, char *a_uri);

/* Set a proxy for a request
 * This will return -1 if the uri is invalid
 */

extern int ghttp_set_proxy(ghttp_request *a_request, char *a_uri);

/* Set a request type
 * This will return -1 if the request type is invalid or
 * unsupported
 */

extern int ghttp_set_type(ghttp_request *a_request, ghttp_type a_type);

/* Set the body.
 * This will return -1 if the request type doesn't support it
 */

extern int ghttp_set_body(ghttp_request *a_request, char *a_body, int a_len);

/* Set whether or not you want to use sync or async mode.
 */

extern int ghttp_set_sync(ghttp_request *a_request, ghttp_sync_mode a_mode);

/* Prepare a request.
 * Call this before trying to process a request or if you change the
 * uri.
 */

extern int ghttp_prepare(ghttp_request *a_request);

/* Set the chunk size
 * You might want to do this to optimize for different connection speeds.
 */

extern void ghttp_set_chunksize(ghttp_request *a_request, int a_size);

/* Set a random request header
 */

extern void ghttp_set_header(ghttp_request *a_request, const char *a_hdr, const char *a_val);

/* Process a request
 */

extern ghttp_status ghttp_process(ghttp_request *a_request);

/* Get the status of a request
 */

extern ghttp_current_status ghttp_get_status(ghttp_request *a_request);

/* Flush the received data (so far) into the response body.  This is
 * useful for asynchronous requests with large responses: you can
 * periodically flush the response buffer and parse the data that's
 * arrived so far.
 */

extern void ghttp_flush_response_buffer(ghttp_request *a_request);

/* Get the value of a random response header
 */

extern const char *ghttp_get_header(ghttp_request *a_request, const char *a_hdr);

/* Get the list of headers that were returned in the response.  You
   must free the returned string values.  This function will return 0
   on success, -1 on some kind of error. */
extern int ghttp_get_header_names(ghttp_request *a_request,char ***a_hdrs, int *a_num_hdrs);

/* Abort a currently running request.  */
extern int ghttp_close(ghttp_request *a_request);

/* Clean a request
 */
extern void ghttp_clean(ghttp_request *a_request);

/* Get the socket associated with a particular connection
 */

extern int ghttp_get_socket(ghttp_request *a_request);

/* get the return entity body
 */

extern char * ghttp_get_body(ghttp_request *a_request);

/* get the returned length
 */

extern int ghttp_get_body_len(ghttp_request *a_request);

/* Get an error message for a request that has failed.
 */

extern const char *ghttp_get_error(ghttp_request *a_request);


/* Parse a date string that is one of the standard
 * date formats
 */

extern time_t ghttp_parse_date(char *a_date);

/* Return the status code.
 */

extern int ghttp_status_code(ghttp_request *a_request);

/* Return the reason phrase.
 */

extern const char *ghttp_reason_phrase(ghttp_request *a_request);

/* Set your username/password pair 
 */

extern int ghttp_set_authinfo(ghttp_request *a_request, const char *a_user, const char *a_pass);
		   

 /* Set your username/password pair for proxy
  */
 
extern int ghttp_set_proxy_authinfo(ghttp_request *a_request,
			 const char *a_user, const char *a_pass);


extern char *ghttp_get_host(ghttp_request *a_request);

/*Get the file name of resource */
extern char *ghttp_get_resource_name(ghttp_request *a_request);

extern ghttp_proc ghttp_get_proc(ghttp_request *a_request);

#ifdef __cplusplus
}
#endif /* __cplusplus */



#define GHTTP_EXTEND	1	/*ghttp extend apply*/

#if	GHTTP_EXTEND

extern int ghttp_download_file(char *path, char *url);

#ifndef strcpy_array
#define strcpy_array(dst, src)	do{\
	strncpy(dst, src, sizeof(dst)-1);\
	dst[sizeof(dst)-1] = '\0';\
	}while(0)
#endif

struct ghttp_result
{
	int http_code;
	FILE *fp;
	char file_path[256];
	unsigned char *buff;
	unsigned int buff_size;
	unsigned char data[2048];
	unsigned int bytes;		// the size of result that saved in buff or fp
	int finish;			// 1: save result finish  2: the work after save result finish. eg: close file
	int (*result_save_func)(ghttp_request *request, struct ghttp_result *result);
};

extern void ghttp_result_destroy(struct ghttp_result *result, int self, int freebuff);

extern struct ghttp_result *ghttp_result_clean(struct ghttp_result *result);

extern int ghttp_result_set(struct ghttp_result *result, char *filepath, void *buff, unsigned int buff_size);

#define ghttp_result_set_default(result)	ghttp_result_set((result), NULL, NULL, 0)

extern int ghttp_get_work(ghttp_request *request, struct ghttp_result *result);

struct ghttp_post_data
{
	FILE *fp;
	char file_path[256];
	unsigned char *buff;
	unsigned int bytes;		// the size of data that stored in buff or fp
	unsigned int post_bytes;
	unsigned int loop;			// the number of times that post data
	unsigned int post_total_bytes;
	int (*post_data_func)(ghttp_request *request, struct ghttp_post_data *data);
};

extern void ghttp_post_data_destory(struct ghttp_post_data *data, int self, int freebuff);

extern int ghttp_post_data_set(struct ghttp_post_data *data, char *filepath, void *buff, unsigned int buff_size);

extern void ghttp_post_data_loop(struct ghttp_post_data *data, unsigned int loop);

extern int ghttp_post_work(ghttp_request *request, struct ghttp_result *result, struct ghttp_post_data *data);

#endif


#endif /* GHTTP_H */
