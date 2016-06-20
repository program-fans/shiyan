
MAKELIB=ar
CC=cc
RM=rm

CFLAGS= -Wall -Iinclude/

src=$(wildcard *.c)
obj=$(src:.c=.o)
TARGET=libmxml

all: $(TARGET).a $(TARGET).so
	make -C test/

$(TARGET).a: $(obj)
	$(MAKELIB) -rv $@ $^
	cp -f $(TARGET).a include/
$(TARGET).so: $(obj)
	$(CC) -o $@ -fPIC -shared $^
#	cp -f $(TARGET).so include/
%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

pack: clean
	zip -qr $(TARGET).zip ./

clean:
	$(RM) -f *.o $(TARGET).a $(TARGET).so
	make -C test/ clean

