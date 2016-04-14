
CC=gcc
LIB=../wf_lib/include/ -lwf -lpthread -lm
GLIB=../ghttp_lib/include/ -lghttp

INCLUDE=../wf_lib/include/
GINCLUDE=../ghttp_lib/include/

all: tools_api

tools_api: tools_api.c
	$(CC) -g tools_api.c -I$(INCLUDE) -I$(GINCLUDE) -L$(LIB) -L$(GLIB) -o $@

pack: clean
	#nothing

clean:
	rm -f *.oi tools_api
