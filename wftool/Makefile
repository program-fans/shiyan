
RM=rm
CC=gcc

LDFLAGS= -lpthread
LDFLAGS+= -L../wf_lib/include/ -lwf -lm
#LDFLAGS+= -L../ghttp_lib/include/ -lghttp

CFLAGS= -I../wf_lib/include/
#CFLAGS+= -I../ghttp_lib/include/

SOURCES = $(wildcard *.c)
OBJS = $(patsubst %.c,%.o,$(SOURCES))

TAG=wftool

.PHONY: $(TAG)

$(TAG):$(OBJS)
	$(CC) $^ $(LDFLAGS) -o $@

%.o:%.c
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	$(RM) -f *.o $(TAG)

install:
	cp -fv wftool /usr/sbin/

uninstall:
	rm -fv /usr/sbin/wftool

