
CC=gcc
LDFLAGS= -lpthread -lm
LDFLAGS+= -L../wf_lib/include/ -lwf
#LDFLAGS+= -L../ghttp_lib/include/ -lghttp

CFLAGS= -I../wf_lib/include/
#CFLAGS= -I../ghttp_lib/include/

SPD=speedtest

all: $(SPD)

$(SPD): $(SPD).c
	$(CC) -g $(SPD).c $(CFLAGS) $(LDFLAGS) -o $@

pack: clean
	#nothing

clean:
	rm -f *.o $(SPD)
