
CC=gcc
LIB=../wf_lib/include/ -lwf -lpthread -lm
GLIB=../ghttp_lib/include/ -lghttp

INCLUDE=../wf_lib/include/
GINCLUDE=../ghttp_lib/include/

all:wolf wftool test

wolf:wolf.c
	$(CC) wolf.c -I$(INCLUDE) -L$(LIB) -o wolf

wftool:wftool.c
	$(CC) wftool.c -I$(INCLUDE) -L$(LIB) -o wftool
	cp -f wftool /usr/sbin/

test:test.c
	$(CC) -g test.c -I$(INCLUDE) -I$(GINCLUDE) -L$(LIB) -L$(GLIB) -o test

pack:
	rm -f *.o
	#zip -qr wolf.zip ./
	echo nothing

clean:
	rm -f *.o
