
CC=gcc
LIB=../wf_lib/lib/libwf.a -lpthread -lm
GLIB=../ghttp_lib/include/libghttp.a

INCLUDE=-I../wf_lib/include/
GINCLUDE=-I../ghttp_lib/include/

all:wolf test

wolf:wolf.c
	$(CC) wolf.c $(INCLUDE) $(LIB) -o wolf

test:test.c
	$(CC) -g test.c $(INCLUDE) $(GINCLUDE) $(LIB) $(GLIB) -o test

clean:
	rm -f *.o wolf test
