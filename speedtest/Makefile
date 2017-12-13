
CC=gcc
LDFLAGS= -lpthread -lm
LDFLAGS+= ../wf_lib/lib/libwf.a
#LDFLAGS+= ../ghttp_lib/lib/libghttp.a

CFLAGS= -I../wf_lib/include/
#CFLAGS+= -I../ghttp_lib/include/

src=$(wildcard *.c)
obj=$(src:.c=.o)

TAG=speedtest

.PHONY: $(TAG)

$(TAG):$(obj)
	$(CC) $^ $(LDFLAGS) -o $@

%.o:%.c
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -f *.o $(TAG)
