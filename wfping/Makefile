
CC=gcc
RM=rm
MAKELIB=ar
MV=mv

SRC = $(wildcard *.c)
OBJS = $(patsubst %.c,%.o,$(SRC))
LIB_OBJS = $(patsubst %.c,%.lib.o,$(SRC))

CFLAGS= -Wall -g
CFLAGS+= -I../wf_lib/include/
CFLAGS+= -Iinclude/

LDFLAGS+= ../wf_lib/lib/libwf.a

LIB=libwfping
TAG=wfping

all: $(TAG) $(LIB).a $(LIB).so

$(LIB).a: $(LIB_OBJS)
	$(MAKELIB) -rv $@ $^
	test -d lib/ || mkdir -p lib
	$(MV) -f $@ lib/

$(LIB).so: $(LIB_OBJS)
	$(CC) -o $@ -fPIC -shared $^
	test -d lib/ || mkdir -p lib
	$(MV) -f $@ lib/

$(LIB_OBJS):%.lib.o:%.c
	$(CC) -c $(CFLAGS) -DLIB_WFPING -DLIB_WFPING_FOR_THREAD $< -o $@

$(TAG): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o:%.c
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	$(RM) -f *.o *.lib.o lib/* $(LIB).a $(LIB).so $(TAG)

