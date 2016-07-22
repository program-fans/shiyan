
CC=gcc
RM=rm

CFLAGS= -Wall

#LDFLAGS= -lpthread -lm

SOURCES = $(wildcard *.c)
OBJS = $(patsubst %.c,%.o,$(SOURCES))

TARGET=test

.PHONY:$(TARGET)

$(TARGET):$(OBJS)
	$(CC) $^ $(LDFLAGS) -o $@

%.o:%.c
	$(CC) -c $(CFLAGS) $< -o $@

pack:clean
	#nothing

clean:
	$(RM) -f *.o $(TARGET)
