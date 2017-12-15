
CC=gcc
LIB=../wf_lib/lib/libwf.a -lpthread -lm
GLIB=../ghttp_lib/lib/libghttp.a
BBWGET_LIB=../bbwget/lib/libbbwget.a

INCLUDE=-I../wf_lib/include/
GINCLUDE=-I../ghttp_lib/include/
BBWGET_INCLUDE=-I../bbwget/include/

all:wolf test

wolf:wolf.c
	$(CC) wolf.c $(INCLUDE) $(LIB) -o wolf

test:test.c
	$(CC) -g test.c $(INCLUDE) $(GINCLUDE) $(BBWGET_INCLUDE) $(LIB) $(GLIB) $(BBWGET_LIB) -o test

clean:
	rm -f *.o wolf test
