
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

LIB=libbbwget
TAG=bbwget

all: $(TAG) $(LIB).a $(LIB).so

$(LIB).a: $(LIB_OBJS)
	$(MAKELIB) -rv $@ $^
	$(MV) -f $@ lib/

$(LIB).so: $(LIB_OBJS)
	$(CC) -o $@ -fPIC -shared $^
	$(MV) -f $@ lib/

$(LIB_OBJS):%.lib.o:%.c
	$(CC) -c $(CFLAGS) -DLIB_BBWGET -DLIB_BBWGET_FOR_THREAD $< -o $@

$(TAG): $(OBJS)
	$(CC) -o $@ $^

%.o:%.c
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	$(RM) -f *.o *.lib.o lib/* $(LIB).a $(LIB).so $(TAG)

