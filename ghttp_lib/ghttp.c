/*
 * ghttp.c -- Implementation of the public interface to http functions
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "ghttp.h"
#include "http_uri.h"
#include "http_hdrs.h"
#include "http_trans.h"
#include "http_req.h"
#include "http_resp.h"
#include "http_date.h"
#include "http_global.h"
#include "http_base64.h"

struct _ghttp_request
{
  http_uri           *uri;
  http_uri           *proxy;
  http_req           *req;
  http_resp          *resp;
  http_trans_conn    *conn; 
  const char         *errstr;
  int                 connected;
  ghttp_proc          proc;
  char               *username;
  char               *password;
  char               *authtoken;
  char               *proxy_username;
  char               *proxy_password;
  char               *proxy_authtoken;
};

static const char *basic_header = "Basic ";

ghttp_request *
ghttp_request_new(void)
{
  struct _ghttp_request *l_return = NULL;

  /* create everything */
  l_return = malloc(sizeof(struct _ghttp_request));
  memset(l_return, 0, sizeof(struct _ghttp_request));
  l_return->uri = http_uri_new();
  l_return->proxy = http_uri_new();
  l_return->req = http_req_new();
  l_return->resp = http_resp_new();
  l_return->conn = http_trans_conn_new();
  return l_return;
}

ghttp_request *ghttp_request_new2(ghttp_type action, char *url, ghttp_sync_mode mode)
{
	ghttp_request *request = NULL;

	if(!url)
		return NULL;
	request = ghttp_request_new();
	if(!request)
		return NULL;
	if( ghttp_set_uri(request, url) < 0)
		goto ERR;
	ghttp_set_type(request, action);
	ghttp_set_sync(request, mode);
	
	return request;
ERR:
	ghttp_request_destroy(request);
	return NULL;
}

ghttp_request *ghttp_request_new_url(char *url)
{
	ghttp_request *request = NULL;

	if(!url)
		return NULL;
	request = ghttp_request_new();
	if(!request)
		return NULL;
	if( ghttp_set_uri(request, url) < 0)
		goto ERR;
	
	return request;
ERR:
	ghttp_request_destroy(request);
	return NULL;
}

void
ghttp_request_destroy(ghttp_request *a_request)
{
  if (!a_request)
    return;
  /* make sure that the socket was shut down. */
  if (a_request->conn->sock >= 0)
    {
      close(a_request->conn->sock);
      a_request->conn->sock = -1;
    }
  /* destroy everything else */
  if (a_request->uri)
    http_uri_destroy(a_request->uri);
  if (a_request->proxy)
    http_uri_destroy(a_request->proxy);
  if (a_request->req)
    http_req_destroy(a_request->req);
  if (a_request->resp)
    http_resp_destroy(a_request->resp);
  if (a_request->conn)
    http_trans_conn_destroy(a_request->conn);
  /* destroy username info. */
  if (a_request->username)
    {
      free(a_request->username);
      a_request->username = NULL;
    }
  if (a_request->password)
    {
      free(a_request->password);
      a_request->password = NULL;
    }
  if (a_request->authtoken)
    {
      free(a_request->authtoken);
      a_request->authtoken = NULL;
    }
  /* destroy proxy authentication */
  if (a_request->proxy_username)
    {
      free(a_request->proxy_username);
      a_request->proxy_username = NULL;
    }
  if (a_request->proxy_password)
    {
      free(a_request->proxy_password);
      a_request->proxy_password = NULL;
    }
  if (a_request->proxy_authtoken)
    {
      free(a_request->proxy_authtoken);
      a_request->proxy_authtoken = NULL;
    }
  if (a_request)
    free(a_request);
  return;
}

int ghttp_uri_validate(char *a_uri)
{
	if (!a_uri)
		return -1;
	/* you can do this... */
	return (http_uri_parse(a_uri, NULL));
}

int ghttp_set_uri(ghttp_request *a_request, char *a_uri)
{
	int l_rv = 0;
	http_uri *l_new_uri = NULL;

	if ((!a_request) || (!a_uri))
		return -1;
	/* set the uri */
	l_new_uri = http_uri_new();
	l_rv = http_uri_parse(a_uri, l_new_uri);
	if (l_rv < 0)
	{
		http_uri_destroy(l_new_uri);
		return -1;
	}
	if (a_request->uri)
	{
		/* check to see if this has been set yet. */
		if (a_request->uri->host &&
			a_request->uri->port &&
			a_request->uri->resource)
		{
			/* check to see if we just need to change the resource */
			if ((!strcmp(a_request->uri->host, l_new_uri->host)) &&
				(a_request->uri->port == l_new_uri->port))
			{
				free(a_request->uri->resource);
				/* make a copy since we're about to destroy it */
				a_request->uri->resource = strdup(l_new_uri->resource);
				http_uri_destroy(l_new_uri);
			}
			else
			{
				goto REPLACE_URI;
			}
		}
		else
		{
			goto REPLACE_URI;
		}
	}
	else
		a_request->uri = l_new_uri;
	
	return 0;
	
REPLACE_URI:
	http_uri_destroy(a_request->uri);
	a_request->uri = l_new_uri;
	return 0;
}

int
ghttp_set_proxy(ghttp_request *a_request, char *a_uri)
{
  int l_rv = 0;
  
  if ((!a_request) || (!a_uri))
    return -1;
  /* set the uri */
  l_rv = http_uri_parse(a_uri, a_request->proxy);
  if (l_rv < 0)
    return -1;
  return 0;
}

int
ghttp_set_type(ghttp_request *a_request, ghttp_type a_type)
{
  int l_return = 0;

  /* check to make sure that the args are ok */
  if (!a_request)
    return -1;
  /* switch on all of the supported types */
  switch(a_type)
    {
    case ghttp_type_get:
      a_request->req->type = http_req_type_get;
      break;
    case ghttp_type_options:
      a_request->req->type = http_req_type_options;
      break;
    case ghttp_type_head:
      a_request->req->type = http_req_type_head;
      break;
    case ghttp_type_post:
      a_request->req->type = http_req_type_post;
      break;
    case ghttp_type_put:
      a_request->req->type = http_req_type_put;
      break;
    case ghttp_type_delete:
      a_request->req->type = http_req_type_delete;
      break;
    case ghttp_type_trace:
      a_request->req->type = http_req_type_trace;
      break;
    case ghttp_type_connect:
      a_request->req->type = http_req_type_connect;
      break;
    case ghttp_type_propfind:
      a_request->req->type = http_req_type_propfind;
      break;
    case ghttp_type_proppatch:
      a_request->req->type = http_req_type_proppatch;
      break;
    case ghttp_type_mkcol:
      a_request->req->type = http_req_type_mkcol;
      break;
    case ghttp_type_copy:
      a_request->req->type = http_req_type_copy;
      break;
    case ghttp_type_move:
      a_request->req->type = http_req_type_move;
      break;
    case ghttp_type_lock:
      a_request->req->type = http_req_type_lock;
      break;
    case ghttp_type_unlock:
      a_request->req->type = http_req_type_unlock;
      break;
    default:
      l_return = -1;
      break;
    }
  return l_return;
}

int
ghttp_set_body(ghttp_request *a_request, char *a_body, int a_len)
{
  /* check to make sure the request is there */
  if (!a_request)
    return -1;
  /* check to make sure the body is there */
  if ((a_len > 0) && (a_body == NULL))
    return -1;
  /* check to make sure that it makes sense */
  if ((a_request->req->type != http_req_type_post) &&
      (a_request->req->type != http_req_type_put) &&
      (a_request->req->type != http_req_type_proppatch) &&
      (a_request->req->type != http_req_type_propfind) &&
      (a_request->req->type != http_req_type_lock))
    return -1;
  /* set the variables */
  a_request->req->body = a_body;
  a_request->req->body_len = a_len;
  return 0;
}

int
ghttp_set_sync(ghttp_request *a_request,
	       ghttp_sync_mode a_mode)
{
  if (!a_request)
    return -1;
  if (a_mode == ghttp_sync)
    a_request->conn->sync = HTTP_TRANS_SYNC;
  else if (a_mode == ghttp_async)
    a_request->conn->sync = HTTP_TRANS_ASYNC;
  else
    return -1;
  return 0;
}

int ghttp_prepare(ghttp_request *a_request)
{
	/* only allow http requests if no proxy has been set */
	if (!a_request->proxy->host && a_request->uri->proto && strcmp(a_request->uri->proto, "http"))
		return -1;
	/* check to see if we have to set up the host information */
	if ((a_request->conn->host == NULL) ||
		(a_request->conn->host != a_request->uri->host) ||
		(a_request->conn->port != a_request->uri->port) ||
		(a_request->conn->proxy_host != a_request->proxy->host) ||
		(a_request->conn->proxy_port != a_request->proxy->port))
	{
		/* reset everything. */
		a_request->conn->host = a_request->uri->host;
		a_request->req->host = a_request->uri->host;
		a_request->req->full_uri = a_request->uri->full;
		a_request->conn->port = a_request->uri->port;
		a_request->conn->proxy_host = a_request->proxy->host;
		a_request->conn->proxy_port = a_request->proxy->port;
		a_request->conn->hostinfo = NULL;
		/* close the socket if it looks open */
		if (a_request->conn->sock >= 0)
		{
			close(a_request->conn->sock);
			a_request->conn->sock = -1;
			a_request->connected = 0;
		}
	}
	/* check to see if we need to change the resource. */
	if ((a_request->req->resource == NULL) || (a_request->req->resource != a_request->uri->resource))
	{
		a_request->req->resource = a_request->uri->resource;
		a_request->req->host = a_request->uri->host;
	}
	/* set the authorization header */
	if ((a_request->authtoken != NULL) && (strlen(a_request->authtoken) > 0))
	{
		http_hdr_set_value(a_request->req->headers, http_hdr_Authorization, a_request->authtoken);
	}
	else
	{
		http_hdr_set_value(a_request->req->headers, http_hdr_WWW_Authenticate, NULL);
	}
	/* set the proxy authorization header */
	if ((a_request->proxy_authtoken != NULL) && (strlen(a_request->proxy_authtoken) > 0))
	{
		http_hdr_set_value(a_request->req->headers, http_hdr_Proxy_Authorization, a_request->proxy_authtoken);
	}
	http_req_prepare(a_request->req);
	
	return 0;
}

ghttp_status ghttp_process(ghttp_request *a_request)
{
	int l_rv = 0;

	ghttpDebug("=======proc: %d \n", a_request->proc);
	if(a_request->proc == ghttp_proc_done)
		return ghttp_done;
	if (a_request->proc == ghttp_proc_none)
		a_request->proc = ghttp_proc_request;
	if (a_request->proc == ghttp_proc_request)
	{
		if (a_request->connected == 0)
		{
			ghttpDebug("connect ... \n");
			if (http_trans_connect(a_request->conn) < 0)
			{
				if (a_request->conn->error_type == http_trans_err_type_errno)
					a_request->errstr = strerror(a_request->conn->error);
				else if(a_request->conn->error_type == http_trans_err_type_host)
					a_request->errstr = http_trans_get_host_error(h_errno);
				return ghttp_error;
			}
			a_request->connected = 1;
		}

		ghttpDebug("send request ... \n");
		l_rv = http_req_send(a_request->req, a_request->conn);
		if (l_rv == HTTP_TRANS_ERR)
		{
			a_request->errstr = a_request->conn->errstr ? a_request->conn->errstr : GHTTP_ERROR_TRANS_SEND;
			return ghttp_error;
		}
		if (l_rv == HTTP_TRANS_NOT_DONE)
			return ghttp_not_done;
		if (l_rv == HTTP_TRANS_DONE)
		{
			a_request->proc = ghttp_proc_response_hdrs;
			if (a_request->conn->sync == HTTP_TRANS_ASYNC)
				return ghttp_not_done;
		}
	}
	
	if (a_request->proc == ghttp_proc_response_hdrs)
	{
		ghttpDebug("read headers ... \n");
		l_rv = http_resp_read_headers(a_request->resp, a_request->conn);
		if (l_rv == HTTP_TRANS_ERR)
		{
			a_request->errstr = a_request->conn->errstr ? a_request->conn->errstr : GHTTP_ERROR_TRANS_READ_HEAD;
			return ghttp_error;
		}
		if (l_rv == HTTP_TRANS_NOT_DONE)
			return ghttp_not_done;
		if (l_rv == HTTP_TRANS_DONE)
		{
			a_request->proc = ghttp_proc_response;
			if (a_request->conn->sync == HTTP_TRANS_ASYNC)
				return ghttp_not_done;
		}
	}
	
	if (a_request->proc == ghttp_proc_response)
	{
		ghttpDebug("read body ... \n");
		l_rv = http_resp_read_body(a_request->resp, a_request->req, a_request->conn);
		if (l_rv == HTTP_TRANS_ERR)
		{
			a_request->errstr = a_request->conn->errstr ? a_request->conn->errstr : GHTTP_ERROR_TRANS_READ_BODY;
			/* make sure that the connected flag is fixed and stuff */
			if (a_request->conn->sock == -1)
				a_request->connected = 0;
			return ghttp_error;
		}
		if (l_rv == HTTP_TRANS_NEXT)
			return ghttp_next;
		if (l_rv == HTTP_TRANS_NOT_DONE)
			return ghttp_not_done;
		if (l_rv == HTTP_TRANS_DONE)
		{
			/* make sure that the connected flag is fixed and stuff */
			if (a_request->conn->sock == -1)
				a_request->connected = 0;
			a_request->proc = ghttp_proc_done;
			return ghttp_done;
		}
	}
	return ghttp_error;
}

ghttp_current_status
ghttp_get_status(ghttp_request *a_request)
{
  ghttp_current_status l_return;

  l_return.proc = a_request->proc;
  if (a_request->proc == ghttp_proc_request)
    {
      l_return.bytes_read = a_request->conn->io_buf_io_done;
      l_return.bytes_total = a_request->conn->io_buf_alloc;
    }
  else if (a_request->proc == ghttp_proc_response_hdrs)
    {
      l_return.bytes_read = 0;
      l_return.bytes_total = 0;
    }
  else if (a_request->proc == ghttp_proc_response)
    {
      if (a_request->resp->content_length > 0)
	{
          l_return.bytes_read = a_request->resp->body_len +
            a_request->conn->io_buf_alloc +
            a_request->resp->flushed_length;
	  l_return.bytes_total = a_request->resp->content_length;
	}
      else
	{
	  l_return.bytes_read = a_request->resp->body_len +
	    a_request->conn->io_buf_alloc +
            a_request->resp->flushed_length;
	  l_return.bytes_total = -1;
	}
    }
  else
    {
      l_return.bytes_read = 0;
      l_return.bytes_total = 0;
    }
  return l_return;
}

void ghttp_flush_response_buffer(ghttp_request *a_request)
{
	//ghttpDebug("a_request->proc: %d \n", a_request->proc);
	if( a_request->proc == ghttp_proc_response || a_request->proc == ghttp_proc_none)
		http_resp_flush(a_request->resp, a_request->conn);
	else if(a_request->proc == ghttp_proc_done && a_request->conn->io_buf_alloc)
		http_resp_flush(a_request->resp, a_request->conn);
}

int
ghttp_close(ghttp_request *a_request)
{
  if (!a_request)
    return -1;
  if (a_request->conn->sock >= 0)
    {
      close(a_request->conn->sock);
      a_request->conn->sock = -1;
    }
  a_request->connected = 0;
  return 0;
}

void
ghttp_clean(ghttp_request *a_request)
{
  http_resp_destroy(a_request->resp);
  a_request->resp = http_resp_new();
  http_req_destroy(a_request->req);
  a_request->req = http_req_new();
  http_trans_buf_reset(a_request->conn);
  a_request->proc = ghttp_proc_none;
  return;
}

void
ghttp_set_chunksize(ghttp_request *a_request, int a_size)
{
  if (a_request && (a_size > 0))
    a_request->conn->io_buf_chunksize = a_size;
}

void ghttp_set_header(ghttp_request *a_request, const char *a_hdr, const char *a_val)
{
	http_hdr_set_value(a_request->req->headers, a_hdr, a_val);
}

const char *ghttp_get_header(ghttp_request *a_request, const char *a_hdr)
{
  return http_hdr_get_value(a_request->resp->headers, a_hdr);
}

int
ghttp_get_header_names(ghttp_request *a_request,
		       char ***a_hdrs, int *a_num_hdrs)
{
  return http_hdr_get_headers(a_request->resp->headers,
			      a_hdrs, a_num_hdrs);
}

const char *
ghttp_get_error(ghttp_request *a_request)
{
  if (a_request->errstr == NULL)
    return "Unknown Error.";
  return a_request->errstr;
}

time_t
ghttp_parse_date(char *a_date)
{
  if (!a_date)
    return 0;
  return (http_date_to_time(a_date));
}

int
ghttp_status_code(ghttp_request *a_request)
{
  if (!a_request)
    return 0;
  return(a_request->resp->status_code);
}

const char *
ghttp_reason_phrase(ghttp_request *a_request)
{
  if (!a_request)
    return 0;
  return(a_request->resp->reason_phrase);
}

int
ghttp_get_socket(ghttp_request *a_request)
{
  if (!a_request)
    return -1;
  return(a_request->conn->sock);
}

/* 2015.10.14  Modify function (ghttp_get_body and ghttp_get_body_len) by wolf-lone
then :
  function (ghttp_get_body and ghttp_get_body_len) must be called after calling function (ghttp_flush_response_buffer).
*/
char *ghttp_get_body(ghttp_request *a_request)
{
	if (!a_request)
		return NULL;
#if 1
	if( a_request->proc == ghttp_proc_none || a_request->proc == ghttp_proc_response ||
		a_request->proc == ghttp_proc_done )
		return a_request->resp->body;
#else	
  if (a_request->proc == ghttp_proc_none)
    return (a_request->resp->body);
  if (a_request->proc == ghttp_proc_response)
    {
      if (a_request->resp->content_length > 0)
	{
	  if (a_request->resp->body_len)
	    return a_request->resp->body;
	  else
	    return a_request->conn->io_buf;
	}
      else
	{
	  return a_request->resp->body;
	}
    }
  #endif
	return NULL;
}

int ghttp_get_body_len(ghttp_request *a_request)
{
	if (!a_request)
		return 0;
#if 1
	if( a_request->proc == ghttp_proc_none || a_request->proc == ghttp_proc_response || 
		a_request->proc == ghttp_proc_done )
		return a_request->resp->body_len;
#else	
	if (a_request->proc == ghttp_proc_none)
		return (a_request->resp->body_len);
	if (a_request->proc == ghttp_proc_response)
	{
		if (a_request->resp->content_length > 0)
		{
			if (a_request->resp->body_len)
				return a_request->resp->body_len;
			else
				return a_request->conn->io_buf_alloc;
		}
		else
		{
			return a_request->resp->body_len;
		}
	}
  #endif
	return 0;
}

int
ghttp_set_authinfo(ghttp_request *a_request,
		   const char *a_user,
		   const char *a_pass)
{
  char *l_authtoken = NULL;
  char *l_final_auth = NULL;
  char *l_auth64 = NULL;

  /* check our args */
  if (!a_request)
    return -1;
  /* if we have a NULL or zero length string in the username
     or password field, blitz the authinfo */
  if ((!a_user) || (strlen(a_user) < 1) ||
      (!a_pass) || (strlen(a_pass)< 1))
    {
      if (a_request->username)
	{
	  free(a_request->username);
	  a_request->username = NULL;
	}
      if (a_request->password)
	{
	  free(a_request->password);
	  a_request->password = NULL;
	}
      if (a_request->authtoken)
	{
	  free(a_request->authtoken);
	  a_request->authtoken = NULL;
	}
      return 0;
    }
  /* encode the string using base64.  Usernames and passwords
     for basic authentication are encoded like this:
     username:password
     That's it.  Easy, huh?
  */
  /* enough for the trailing \0 and the : */
  l_authtoken = malloc(strlen(a_user) + strlen(a_pass) + 2);
  memset(l_authtoken, 0, (strlen(a_user) + strlen(a_pass) + 2));
  sprintf(l_authtoken, "%s:%s", a_user, a_pass);
  l_auth64 = http_base64_encode(l_authtoken);
  if (!l_auth64)
    {
      free(l_authtoken);
      return -1;
    }
  /* build the final header */
  l_final_auth = malloc(strlen(l_auth64) + strlen(basic_header) + 1);
  memset(l_final_auth, 0, (strlen(l_auth64) + strlen(basic_header) + 1));
  strcat(l_final_auth, basic_header);
  strcat(l_final_auth, l_auth64);
  free(l_auth64);
  free(l_authtoken);
  /* copy the strings into the request */

  if (a_request->username) free(a_request->username);
  if (a_request->password) free(a_request->password);
  if (a_request->authtoken) free(a_request->authtoken);
  a_request->username = strdup(a_user);
  a_request->password = strdup(a_pass);
  a_request->authtoken = l_final_auth;

  return 0;
}


int
ghttp_set_proxy_authinfo(ghttp_request *a_request,
			 const char *a_user,
			 const char *a_pass)
{
  char *l_authtoken = NULL;
  char *l_final_auth = NULL;
  char *l_auth64 = NULL;
  
  /* check our args */
  if (!a_request)
    return -1;
  /* if we have a NULL or zero length string in the username
     or password field, blitz the authinfo */
  if ((!a_user) || (strlen(a_user) < 1) ||
      (!a_pass) || (strlen(a_pass)< 1))
    {
      if (a_request->proxy_username)
	{
	  free(a_request->proxy_username);
	  a_request->proxy_username = NULL;
	}
      if (a_request->proxy_password)
	{
	  free(a_request->proxy_password);
	  a_request->proxy_password = NULL;
	}
      if (a_request->proxy_authtoken)
	{
	  free(a_request->proxy_authtoken);
	  a_request->proxy_authtoken = NULL;
	}
      return 0;
    }
  /* encode the string using base64.  Usernames and passwords
     for basic authentication are encoded like this:
     username:password
     That's it.  Easy, huh?
  */
  /* enough for the trailing \0 and the : */
  l_authtoken = malloc(strlen(a_user) + strlen(a_pass) + 2);
  memset(l_authtoken, 0, (strlen(a_user) + strlen(a_pass) + 2));
  sprintf(l_authtoken, "%s:%s", a_user, a_pass);
  l_auth64 = http_base64_encode(l_authtoken);
  if (!l_auth64)
    {
      free(l_authtoken);
      return -1;
    }
  /* build the final header */
  l_final_auth = malloc(strlen(l_auth64) + strlen(basic_header) + 1);
  memset(l_final_auth, 0, (strlen(l_auth64) + strlen(basic_header) + 1));
  strcat(l_final_auth, basic_header);
  strcat(l_final_auth, l_auth64);
  free(l_auth64);
  free(l_authtoken);
  /* copy the strings into the request */
  if (a_request->proxy_username) free(a_request->proxy_username);
  if (a_request->proxy_password) free(a_request->proxy_password);
  if (a_request->proxy_authtoken) free(a_request->proxy_authtoken);
  a_request->proxy_username = strdup(a_user);
  a_request->proxy_password = strdup(a_pass);
  a_request->proxy_authtoken = l_final_auth;
  
  return 0;
}

char *ghttp_get_host(ghttp_request *a_request)
{
	if(a_request && a_request->uri && a_request->uri->host)
		return a_request->uri->host;
	else
		return NULL;
}

char *ghttp_get_resource_name(ghttp_request *a_request)
{
	char *ptr = NULL;
	
	if(a_request && a_request->uri && a_request->uri->resource)
	{
		if( strcmp(a_request->uri->resource, "/") == 0 )
			return NULL;
		ptr = strrchr(a_request->uri->resource, '/');
		if(ptr)
			return ++ptr;
		else
			return NULL;
	}
	else
		return NULL;
}

ghttp_proc ghttp_get_proc(ghttp_request *a_request)
{
	return a_request ? a_request->proc : ghttp_proc_none;
}



#if	GHTTP_EXTEND
int ghttp_work_httpheader(ghttp_request *request, ghttp_type request_type)
{
	int ret = 0;
	ghttp_status req_status;
	ghttp_proc req_proc;

	if(!request)
		return -1;
	ghttp_set_type(request, request_type);
	ghttp_set_sync(request, ghttp_async);
	if( ghttp_prepare(request) < 0 ){
		ret = -3;
		goto END;
	}

	do
	{
		req_status = ghttp_process(request);
		if( req_status == ghttp_error ){
			ghttpDebug("%s \n", ghttp_get_error(request));
			ret = -3;
			goto END;
		}
		else
		{
			req_proc = ghttp_get_proc(request);
			if( req_proc == ghttp_proc_response || req_proc == ghttp_proc_done ){
				break;
			}
		}
	}while (req_status == ghttp_not_done);
		
END:	
	return ret;
}


int ghttp_download_file(char *path, char *url)
{
	ghttp_request *request = NULL;
	FILE * pFile=NULL;
	char *buf=NULL;
	int ret = 0;

	ghttp_status req_status;
	ghttp_proc req_proc;
	int bytes_read=0,recvbytes=0;
	int status_code=0;
	char *redirect = NULL;
#if GHTTP_DEBUG
	char *tmp_pchar = NULL;
#endif

	request = ghttp_request_new();
	if( ghttp_set_uri(request, url) < 0 ){
			ghttpDebug("invalid url: %s \n", url);
       		ret = -1;
			goto END;
	}
	
	if(!path)
		path = ghttp_get_resource_name(request);
	if(!path)
		path = "httpget.html";
	
	pFile = fopen ( path , "wb" );
	if(pFile == NULL){
		ghttpDebug("error: %s [%s]\n", strerror(errno), path);
		ret = -2;
		goto END;
	}
	ghttpDebug("host: %s \n", ghttp_get_host(request));
	if( ghttp_set_type(request, ghttp_type_get) < 0 ){
    		ret = -3;
		goto END;
	}
	if (ghttp_set_sync(request, ghttp_async) < 0){
		ret = -3;
		goto END;
	}
	if( ghttp_prepare(request) < 0 ){
		ret = -3;
		goto END;
	}

	do
	{
		req_status = ghttp_process(request);
		if( req_status == ghttp_error ){
			ghttpDebug("%s \n", ghttp_get_error(request));
			ret = -4;
			goto END;
		}
		else
		{
			if( req_status == ghttp_done )
			{
				status_code = ghttp_status_code(request);
				if(status_code != 200){
					fclose(pFile);
					pFile = NULL;
					break;
				}
			}

			req_proc = ghttp_get_proc(request);
			if( req_proc == ghttp_proc_response || req_proc == ghttp_proc_done )
			{
			#if GHTTP_DEBUG
				if( !tmp_pchar )
				{
					tmp_pchar = (char *)ghttp_get_header(request, "Content-Length");
					ghttpDebug("Content-Length: %s \n", tmp_pchar ? tmp_pchar : "null");
					tmp_pchar = (char *)ghttp_get_header(request, "Transfer-Encoding");
					ghttpDebug("Transfer-Encoding: %s \n", tmp_pchar ? tmp_pchar : "null");
					tmp_pchar = (char *)ghttp_get_header(request, "Content-Encoding");
					ghttpDebug("Content-Encoding: %s \n", tmp_pchar ? tmp_pchar : "null");
					tmp_pchar = (char *)1;
					
					ghttpDebug("recvbytes: ");
				}
			#endif
			
				ghttp_flush_response_buffer(request);
				if(ghttp_get_body_len(request) > 0)
				{
					buf = ghttp_get_body(request);
					bytes_read = ghttp_get_body_len(request);
					recvbytes += bytes_read;
					if(buf)
						fwrite(buf,bytes_read,1,pFile);
				}

				ghttpDebug("%d", recvbytes);
			}
		}
	}while (req_status == ghttp_not_done);

	//ret = status_code;
	switch(status_code)
	{
	case 200:
	default:
		break;
	case 302:
		buf = (char *)ghttp_get_header(request, "Location");
		if(buf){
			redirect = (char *)malloc(strlen(buf)+1);
			if(redirect == NULL){
				ret = -1;
				goto END;
			}
			strcpy(redirect, buf);
		}
		break;
	}
	
END:
	ghttp_request_destroy(request);
    	if(pFile)
		fclose(pFile);
	if(redirect){
		ghttpDebug("redirect: %s \n", redirect);
		ret = ghttp_download_file(path, redirect);
		free(redirect);
	}
	
	return ret;
}



static ghttp_request *ghttp_request_redirect(ghttp_request *cur_request, char *new_url)
{
	ghttp_request *request = NULL;
	
	if (!cur_request || !cur_request->req || !cur_request->conn)
		return NULL;

	request = ghttp_request_new();
	if(!request)
		return NULL;

	if( ghttp_set_uri(request, new_url) < 0)
		goto ERR;
	ghttp_set_type(request, cur_request->req->type);
	ghttp_set_sync(request, cur_request->conn->sync);

	return request;
ERR:
	ghttp_request_destroy(request);
	return NULL;
}

void ghttp_result_destroy(struct ghttp_result *result, int self, int freebuff)
{
	if(!result)
		return;
	if(freebuff && result->buff && (result->buff != (&result->data[0])) )
		free(result->buff);
	if(self)
		free(result);
}

struct ghttp_result *ghttp_result_clean(struct ghttp_result *result)
{
	if(!result)
		return NULL;
	if(result->fp){
		fclose(result->fp);
		result->fp = NULL;
	}
	if(strlen(result->file_path) > 0){
		result->fp = fopen(result->file_path , "wb");
		if(NULL == result->fp){
			return NULL;
		}
	}

	if(result->buff)
		memset(result->buff, 0, result->buff_size);
	memset(result->data, 0, sizeof(result->data));
	result->http_code = 0;
	result->bytes = 0;
	result->finish = 0;

	return result;
}

static int ghttp_result_save_buff(ghttp_request *request, struct ghttp_result *result)
{
	char *buf = NULL;
	int bytes_read = 0;
	int tmp = 0;
	
	if(!request || !result)
		return -1;

	if(result->finish){
		return 0;
	}

	ghttp_flush_response_buffer(request);
	if(ghttp_get_body_len(request) > 0)
	{
		buf = ghttp_get_body(request);
		bytes_read = ghttp_get_body_len(request);
		//ghttpDebug("buf: %p, bytes_read: %d \n", buf, bytes_read);
		if(buf){
			tmp = result->bytes + bytes_read;
			if(tmp >= result->buff_size){
				bytes_read = tmp - result->bytes;
				result->finish = 1;
			}
			memcpy(result->buff + result->bytes, buf, bytes_read);
			result->bytes += bytes_read;
		}
	}

	return 0;
}

static int ghttp_result_save_file(ghttp_request *request, struct ghttp_result *result)
{
	char *buf = NULL;
	int bytes_read = 0;
	
	if(!request || !result)
		return -1;

	if(result->finish){
		fclose(result->fp);
		result->fp = NULL;
		return 0;
	}

	ghttp_flush_response_buffer(request);
	if(ghttp_get_body_len(request) > 0)
	{
		buf = ghttp_get_body(request);
		bytes_read = ghttp_get_body_len(request);
		
		if(buf){
			if( fwrite(buf, bytes_read, 1, result->fp) == bytes_read)
				result->bytes += bytes_read;
		}
	}

	return 0;
}

int ghttp_result_set(struct ghttp_result *result, char *filepath, void *buff, unsigned int buff_size)
{
	if(!result)
		return -1;
	
	memset(result, 0, sizeof(result));
	if(filepath && strlen(filepath) > 0){
		strcpy_array(result->file_path, filepath);
		result->fp = fopen(result->file_path , "wb");
		if(NULL == result->fp){
			return -1;
		}
		result->result_save_func = ghttp_result_save_file;
		return 0;
	}
	
	if(buff){
		result->buff = (unsigned char *)buff;
		result->buff_size = buff_size;
	}
	else{
		if(buff_size <= sizeof(result->data)){
			result->buff = &(result->data[0]);
			result->buff_size = sizeof(result->data);
		}
		else{
			result->buff = (unsigned char *)malloc(buff_size);
			if(NULL == result->buff){
				return -1;
			}
		}
	}
	
	result->result_save_func = ghttp_result_save_buff;

	return 0;
}

static void ghttp_result_recv_finish(ghttp_request *request, struct ghttp_result *result)
{
	if(NULL == result || result->finish == 2 )
		return;
	result->finish = 1;
	result->result_save_func(request, result);
	result->finish = 2;
}

static void ghttp_result_recv(ghttp_request *request, struct ghttp_result *result)
{
	if(NULL == result)
		ghttp_flush_response_buffer(request);
	else
		result->result_save_func(request, result);
}

int ghttp_get_work(ghttp_request *request, struct ghttp_result *result)
{
	int ret = 0;
	ghttp_status req_status;
	ghttp_proc req_proc;
	int status_code = 0;
	ghttp_request *redirect_request;
	char *redirect = NULL, *buf = NULL;

	#if GHTTP_DEBUG
	char *tmp_pchar = NULL;
	#endif

	if(!request)
		return -1;
	ghttp_set_type(request, ghttp_type_get);
	ghttp_set_sync(request, ghttp_async);
	if( ghttp_prepare(request) < 0 ){
		ret = -3;
		goto END;
	}

	do
	{
		req_status = ghttp_process(request);
		if( req_status == ghttp_error ){
			ghttpDebug("%s \n", ghttp_get_error(request));
			ret = -3;
			goto END;
		}
		else
		{
			if( req_status == ghttp_done )
			{
				status_code = ghttp_status_code(request);
				if(status_code != 200){
					ghttp_result_recv_finish(request, result);
					break;
				}
			}

			req_proc = ghttp_get_proc(request);
			if( req_proc == ghttp_proc_response || req_proc == ghttp_proc_done )
			{
			#if GHTTP_DEBUG
				if( !tmp_pchar )
				{
					tmp_pchar = (char *)ghttp_get_header(request, "Content-Length");
					ghttpDebug("Content-Length: %s \n", tmp_pchar ? tmp_pchar : "null");
					tmp_pchar = (char *)ghttp_get_header(request, "Transfer-Encoding");
					ghttpDebug("Transfer-Encoding: %s \n", tmp_pchar ? tmp_pchar : "null");
					tmp_pchar = (char *)ghttp_get_header(request, "Content-Encoding");
					ghttpDebug("Content-Encoding: %s \n", tmp_pchar ? tmp_pchar : "null");
					tmp_pchar = (char *)ghttp_get_header(request, "Content-Type");
					ghttpDebug("Content-Type: %s \n", tmp_pchar ? tmp_pchar : "null");
					tmp_pchar = (char *)1;
				}
			#endif
				ghttp_result_recv(request, result);
			}
		}
	}while (req_status == ghttp_not_done);
	
	switch(status_code)
	{
	case 200:
	default:
		break;
	case 302:
		buf = (char *)ghttp_get_header(request, "Location");
		if(buf){
			redirect = (char *)malloc(strlen(buf)+1);
			if(redirect == NULL){
				ret = -2;
				goto END;
			}
			strcpy(redirect, buf);
		}
		break;
	}
	
END:
	if(result)
		result->http_code = status_code;
	ghttp_result_recv_finish(request, result);
	
	if(redirect){
		ghttpDebug("redirect: %s \n", redirect);
		redirect_request = ghttp_request_redirect(request, redirect);
		ghttp_request_destroy(request);
		free(redirect);
		ret = ghttp_get_work(redirect_request, ghttp_result_clean(result));
	}
	else
		ghttp_request_destroy(request);
	
	return ret;
}





void ghttp_post_data_destory(struct ghttp_post_data *data, int self, int freebuff)
{
	if(!data)
		return;
	if(data->fp){
		fclose(data->fp);
		data->fp = NULL;
	}
	if(freebuff && data->buff)
		free(data->buff);
	if(self)
		free(data);
}

static int ghttp_post_data_buff(ghttp_request *request, struct ghttp_post_data *data)
{
	unsigned int post_len = 0;
	if(!request || !data || !data->buff || !data->bytes)
		return -1;
	if(!data->loop){
		return 0;
	}

	post_len = data->bytes - data->post_bytes;
	if(post_len == 0)
		return 0;
	else if(post_len > CONN_IO_BUF_CHUNKSIZE_DEFAULT)
		post_len = CONN_IO_BUF_CHUNKSIZE_DEFAULT;
	ghttp_set_body(request, (char *)data->buff + data->post_bytes, post_len);
	
	data->post_bytes += post_len;
	if(data->post_bytes == data->bytes){
		data->post_bytes = 0;
		--data->loop;
		data->post_total_bytes += data->bytes;
	}
	
	return 0;
}

static unsigned char ghttp_chunk[CONN_IO_BUF_CHUNKSIZE_DEFAULT];
static int ghttp_post_data_file(ghttp_request *request, struct ghttp_post_data *data)
{
	size_t r_read;
	if(!request || !data || !data->buff || !data->bytes)
		return -1;
	if(!data->loop){
		if(data->fp){
			fclose(data->fp);
			data->fp = NULL;
		}
		return 0;
	}

	while(1){
		r_read = fread(ghttp_chunk, 1, CONN_IO_BUF_CHUNKSIZE_DEFAULT, data->fp);
		if(r_read >= 0)
			break;
		else if(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			continue;
		else
			return -1;
	}
	
	if(r_read > 0){
		ghttp_set_body(request, (char *)ghttp_chunk, r_read);
		data->post_bytes += r_read;
		if(data->post_bytes == data->bytes){
			data->post_bytes = 0;
			--data->loop;
			data->post_total_bytes += data->bytes;
			fseek(data->fp, 0, SEEK_SET);
		}
	}
	else
		ghttp_set_body(request, NULL, 0);

	return 0;
}

int ghttp_post_data_set(struct ghttp_post_data *data, char *filepath, void *buff, unsigned int buff_size)
{
	if(!data)
		return -1;
	
	memset(data, 0, sizeof(data));
	data->loop = 1;
	if(filepath && strlen(filepath) > 0){
		strcpy_array(data->file_path, filepath);
		data->fp = fopen(data->file_path , "rb");
		if(NULL == data->fp){
			return -1;
		}
		fseek(data->fp, 0, SEEK_END);
		data->bytes = (unsigned int)ftell(data->fp);
		fseek(data->fp, 0, SEEK_SET);
		data->post_data_func = ghttp_post_data_buff;
		return 0;
	}
	
	if(buff){
		data->buff = (unsigned char *)buff;
		data->bytes = buff_size;
	}
	else{
		return -1;
	}
	
	data->post_data_func = ghttp_post_data_file;

	return 0;
}

void ghttp_post_data_loop(struct ghttp_post_data *data, unsigned int loop)
{
	if(data)
		data->loop = loop + 1;
}

int ghttp_post_work(ghttp_request *request, struct ghttp_result *result, struct ghttp_post_data *data)
{
	int ret = 0;
	ghttp_status req_status;
	ghttp_proc req_proc;
	int status_code = 0;
//	ghttp_request *redirect_request;
//	char *redirect = NULL, *buf = NULL;

	#if GHTTP_DEBUG
	char *tmp_pchar = NULL;
	#endif

	if(!request || !data)
		return -1;
	ghttp_set_type(request, ghttp_type_post);
	ghttp_set_sync(request, ghttp_async);
	if( ghttp_prepare(request) < 0 ){
		ret = -3;
		goto END;
	}

	do
	{
		req_status = ghttp_process(request);
		if( req_status == ghttp_error ){
			ghttpDebug("%s \n", ghttp_get_error(request));
			ret = -3;
			goto END;
		}
		else
		{
			if(req_status == ghttp_next ){
				data->post_data_func(request, data);
			}
			if( req_status == ghttp_done )
			{
				status_code = ghttp_status_code(request);
				if(status_code != 200){
					ghttp_result_recv_finish(request, result);
					break;
				}
			}

			req_proc = ghttp_get_proc(request);
			if( req_proc == ghttp_proc_response || req_proc == ghttp_proc_done )
			{
			#if GHTTP_DEBUG
				if( !tmp_pchar )
				{
					tmp_pchar = (char *)ghttp_get_header(request, "Content-Length");
					ghttpDebug("Content-Length: %s \n", tmp_pchar ? tmp_pchar : "null");
					tmp_pchar = (char *)ghttp_get_header(request, "Transfer-Encoding");
					ghttpDebug("Transfer-Encoding: %s \n", tmp_pchar ? tmp_pchar : "null");
					tmp_pchar = (char *)ghttp_get_header(request, "Content-Encoding");
					ghttpDebug("Content-Encoding: %s \n", tmp_pchar ? tmp_pchar : "null");
					tmp_pchar = (char *)ghttp_get_header(request, "Content-Type");
					ghttpDebug("Content-Type: %s \n", tmp_pchar ? tmp_pchar : "null");
					tmp_pchar = (char *)1;
				}
			#endif
				ghttp_result_recv(request, result);
			}
		}
	}while (req_status == ghttp_not_done);
	
END:
	ghttpDebug("http_code: %d \n", status_code);
	if(ret == 0 && (status_code < 200 || status_code >= 300))
		ret = -3;
	if(result)
		result->http_code = status_code;
	ghttp_result_recv_finish(request, result);

	ghttp_request_destroy(request);
	
	return ret;
}
#endif

