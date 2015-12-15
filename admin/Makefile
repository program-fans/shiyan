
CC=gcc
LIB=../wf_lib/include/ -lwf -lpthread
INCLUDE=../wf_lib/include/

all:wolf test

wolf:wolf.c
	$(CC) wolf.c -I$(INCLUDE) -L$(LIB) -o wolf

test:test.c
	$(CC) test.c -I$(INCLUDE) -L$(LIB) -o test

pack:
	rm -f *.o
	#zip -qr wolf.zip ./
	echo nothing

clean:
	rm -f *.o
