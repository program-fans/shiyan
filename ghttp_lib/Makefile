
MAKELIB=ar
CC=cc
RM=rm
MV=mv

CFLAGS= -Wall -Iinclude/

src=$(wildcard *.c)
obj=$(src:.c=.o)
TARGET=libghttp

all: $(TARGET).a $(TARGET).so

$(TARGET).a: $(obj)
	$(MAKELIB) -rv $@ $^
	test -d lib/ || mkdir -p lib
	$(MV) -f $@ lib/

$(TARGET).so: $(obj)
	$(CC) -o $@ -fPIC -shared $^
	test -d lib/ || mkdir -p lib
	$(MV) -f $@ lib/

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	$(RM) -f *.o lib/* $(TARGET).a $(TARGET).so

