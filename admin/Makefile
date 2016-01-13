
CC=gcc
LIB=../wf_lib/include/ -lwf -lpthread
INCLUDE=../wf_lib/include/

all:wolf wftool test

wolf:wolf.c
	$(CC) wolf.c -I$(INCLUDE) -L$(LIB) -o wolf

wftool:wftool.c
	$(CC) wftool.c -I$(INCLUDE) -L$(LIB) -o wftool
	cp -f wftool /usr/sbin/

test:test.c
	$(CC) test.c -I$(INCLUDE) -L$(LIB) -o test

pack:
	rm -f *.o
	#zip -qr wolf.zip ./
	echo nothing

clean:
	rm -f *.o
