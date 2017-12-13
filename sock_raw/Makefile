
RM=rm
CC=gcc

LDFLAGS= -lpthread
LDFLAGS+= ../wf_lib/lib/libwf.a -lm
#LDFLAGS+= ../ghttp_lib/lib/libghttp.a

CFLAGS= -I../wf_lib/include/
#CFLAGS= -I../ghttp_lib/include/

SOURCES = $(wildcard *.c)
OBJS = $(patsubst %.c,%.o,$(SOURCES))

TAG=net_monitor

.PHONY: $(TAG)

$(TAG):$(OBJS)
	$(CC) $^ $(LDFLAGS) -o $@

%.o:%.c
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	$(RM) -f *.o $(TAG)
	$(RM) -rf log/
