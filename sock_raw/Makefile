
CC=gcc
LIB=../wf_lib/include/ -lwf -lpthread -lm
INCLUDE=../wf_lib/include/

TARGET=net_monitor
OBJS=net_monitor.o filter.o misc.o peek.o

all:$(TARGET)

$(TARGET):$(OBJS)
	$(CC) $(OBJS) -L$(LIB) -o $(TARGET)

%.o:%.c
	$(CC) -c -I$(INCLUDE) -L$(LIB) $< -o $@

pack:
	rm -f *.o
	rm -f log/*
	zip -qr $(TARGET).zip ./

clean:
	rm -f *.o
