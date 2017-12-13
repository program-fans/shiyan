
MAKELIB=ar
CC=cc
RM=rm
MV=mv

CFLAGS= -Wall -Iinclude/

src=$(wildcard *.c)
obj=$(src:.c=.o)
TARGET=libmxml

all: $(TARGET).a $(TARGET).so
	make -C test/

$(TARGET).a: $(obj)
	$(MAKELIB) -rv $@ $^
	$(MV) -f $@ lib/

$(TARGET).so: $(obj)
	$(CC) -o $@ -fPIC -shared $^
	$(MV) -f $@ lib/

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	$(RM) -f *.o lib/* $(TARGET).a $(TARGET).so
	make -C test/ clean

