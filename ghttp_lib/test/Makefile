
CC=gcc
LIB=../include/ -lghttp
INCLUDE=../include/

TARGET=ghttp_get_file
OBJS=ghttp_get_file.o

all:$(TARGET)

$(TARGET):$(OBJS)
	$(CC) $(OBJS) -L$(LIB) -o $(TARGET)

%.o:%.c
	$(CC) -c -I$(INCLUDE) -L$(LIB) $< -o $@

clean:
	rm -f *.o
