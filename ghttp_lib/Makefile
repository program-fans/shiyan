
MAKELIB=ar
CC=cc
RM=rm

src=$(wildcard *.c)
obj=$(src:.c=.o)
TARGET=libghttp

all: $(TARGET).a $(TARGET).so

$(TARGET).a: $(obj)
	$(MAKELIB) -rv $@ $^
	cp -f $(TARGET).a include/
$(TARGET).so: $(obj)
	$(CC) -o $@ -fPIC -shared $^
#	cp -f $(TARGET).so include/
%.o: %.c
	$(CC) -c -Iinclude/ $< -o $@

pack:
	$(RM) -f *.o
	zip -qr $(TARGET).zip ./

clean:
	$(RM) -f *.o $(TARGET).a $(TARGET).so

