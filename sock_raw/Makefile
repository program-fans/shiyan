
CC=gcc
WFLIB=../wf_lib/include/ -lwf
LIB=-lpthread -lm
INCLUDE=../wf_lib/include/

TARGET=net_monitor
OBJS=net_monitor.o filter.o misc.o peek.o

all:$(TARGET)

$(TARGET):$(OBJS)
	$(CC) $(OBJS) -L$(WFLIB) $(LIB) -o $(TARGET)
#	$(CC) $(OBJS) ../wf_lib/libwf.so $(LIB) -o $(TARGET)
%.o:%.c
	$(CC) -c -I$(INCLUDE) $< -o $@

pack: clean
	rm -f log/*
	zip -qr $(TARGET).zip ./

clean:
	rm -f *.o
