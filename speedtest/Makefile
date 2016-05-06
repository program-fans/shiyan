
CC=gcc
LIB=../wf_lib/include/ -lwf -lpthread -lm
GLIB=../ghttp_lib/include/ -lghttp

INCLUDE=../wf_lib/include/
GINCLUDE=../ghttp_lib/include/

SPD=speedtest

all: $(SPD)

$(SPD): $(SPD).c
	$(CC) -g $(SPD).c -I$(INCLUDE) -I$(GINCLUDE) -L$(LIB) -L$(GLIB) -o $@

pack: clean
	#nothing

clean:
	rm -f *.o $(SPD)
