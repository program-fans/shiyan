
CC=gcc
#LDFLAGS= -lpthread -lm
#LDFLAGS+= -L../../wf_lib/include/ -lwf
#LDFLAGS+= -L../../ghttp_lib/include/ -lghttp

#CFLAGS= -I../../wf_lib/include/
#CFLAGS+= -I../../ghttp_lib/include/

SOURCES = $(wildcard *.c)
OBJS = $(patsubst %.c,%.o,$(SOURCES))

TAG=inotify

.PHONY: $(TAG)

$(TAG):$(OBJS)
	$(CC) $^ $(LDFLAGS) -o $@

%.o:%.c
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -f *.o $(TAG)
