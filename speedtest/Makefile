
CC=gcc
LDFLAGS= -lpthread -lm
LDFLAGS+= -L../wf_lib/include/ -lwf
#LDFLAGS+= -L../ghttp_lib/include/ -lghttp

CFLAGS= -I../wf_lib/include/
#CFLAGS+= -I../ghttp_lib/include/

src=$(wildcard *.c)
obj=$(src:.c=.o)

TAG=speedtest

.PHONY: $(TAG)

$(TAG):$(obj)
	$(CC) $^ $(LDFLAGS) -o $@

%.o:%.c
	$(CC) -c $(CFLAGS) $< -o $@

pack: clean
	#nothing

clean:
	rm -f *.o $(SPD)
