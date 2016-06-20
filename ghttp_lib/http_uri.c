/*
 * http_uri.c --- Contains functions to parse uri's
 * Created: Christopher Blizzard <blizzard@appliedtheory.com>, 4-Jul-98
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

#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "http_uri.h"

typedef enum uri_parse_state_tag
{
  parse_state_read_host = 0,
  parse_state_read_port,
  parse_state_read_resource
} uri_parse_state;

/*2015.10.12  Add by wolf-lone*/
int http_uri_parse(char *a_string, http_uri *a_uri)
{
#define DEFAULT_PORT	80
#define check_null(ptr)	do{ if(ptr == NULL)	 goto ec;} while(0)

	char *str = NULL;
	char *host_s = NULL;
	char *source_s = NULL;
	char *port_s = NULL;
	int len = 0;
	char  tmp_port[6];
	
	check_null(a_string);
	check_null(a_uri);

	a_uri->full = strdup(a_string);
	if(a_uri->full == NULL)
		goto ec;
	
	str = strchr(a_string, ':');
	check_null(str);
	if (strncmp(str, "://", 3) != 0)
		goto ec;

	len = str - a_string;
	a_uri->proto = (char *)malloc(len + 1);
	memcpy(a_uri->proto, a_string, len);
	a_uri->proto[len] = '\0';

	host_s = &str[3];
	if(host_s == NULL || strlen(host_s) == 0)
		goto ec;

	port_s = strchr(host_s, ':');
	source_s = strchr(host_s, '/');

	if(port_s == NULL && source_s == NULL)
	{
		a_uri->host = strdup(host_s);
		check_null(a_uri->host);
		a_uri->port = DEFAULT_PORT;
		
		a_uri->resource = strdup("/");
		check_null(a_uri->resource);
		
		return 0;
	}
	
	if(port_s != NULL || source_s != NULL)
	{
		if(port_s != NULL)
			str = port_s;
		else
			str = source_s;
		
		len = str - host_s;
		a_uri->host = (char *)malloc(len + 1);
		check_null(a_uri->host);
		memcpy(a_uri->host, host_s, len);
		a_uri->host[len] = '\0';

		if(port_s != NULL)
		{
			++port_s;
			if(source_s != NULL)
			{
				len = source_s - port_s;
				if(len >= sizeof(tmp_port))
					goto ec;
				memcpy(tmp_port, port_s, len);
				tmp_port[len] = '\0';
				a_uri->port = atoi(tmp_port);
			}
			else
				a_uri->port = atoi(port_s);
		}
		else
			a_uri->port = DEFAULT_PORT;
		
		if(source_s != NULL)
			a_uri->resource = strdup(source_s);
		else
			a_uri->resource = strdup("/");
		check_null(a_uri->resource);

		return 0;
	}
ec:
	return -1;
}

http_uri *http_uri_new(void)
{
	http_uri *l_return = NULL;

	l_return = (http_uri *)malloc(sizeof(http_uri));
	l_return->full = NULL;
	l_return->proto = NULL;
	l_return->host = NULL;
	l_return->port = 80;
	l_return->resource = NULL;
	return l_return;
}

void http_uri_destroy(http_uri *a_uri)
{
	if (a_uri->full) {
		free(a_uri->full);
		a_uri->full = NULL;
	}
	if (a_uri->proto) {
		free(a_uri->proto);
		a_uri->proto = NULL;
	}
	if (a_uri->host) {
		free(a_uri->host);
		a_uri->host = NULL;
	}
	if (a_uri->resource) {
		free(a_uri->resource);
		a_uri->resource = NULL;
	}
	free(a_uri);
}

