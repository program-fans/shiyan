
CC=gcc
LIB=../wf_lib/include/ -lwf -lpthread -lm
GLIB=../ghttp_lib/include/ -lghttp

INCLUDE=../wf_lib/include/
GINCLUDE=../ghttp_lib/include/

all:wolf test

wolf:wolf.c
	$(CC) wolf.c -I$(INCLUDE) -L$(LIB) -o wolf

test:test.c
	$(CC) -g test.c -I$(INCLUDE) -I$(GINCLUDE) -L$(LIB) -L$(GLIB) -o test

clean:
	rm -f *.o wolf test
