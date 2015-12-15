
CC=gcc
LIB=../ghttp_lib/include/ -lghttp
INCLUDE=../ghttp_lib/include/

TARGET=cgicall
OBJS=cgi_call.o

all:$(TARGET)

$(TARGET):$(OBJS)
	$(CC) $(OBJS) -L$(LIB) -o $(TARGET)

%.o:%.c
	$(CC) -c -I$(INCLUDE) -L$(LIB) $< -o $@
pack:
	rm -f *.o
	#zip -qr cgi_test.zip ./
	echo nothing
clean:
	rm -f *.o
