
RM=rm
CC=gcc

LDFLAGS= -lpthread
LDFLAGS+= ../wf_lib/lib/libwf.a -lm
#LDFLAGS+= ../ghttp_lib/lib/libghttp.a

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

