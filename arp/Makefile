
CC=gcc
LIB=../wf_lib/include/ -lwf -lpthread
INCLUDE=../wf_lib/include/

all:arp_cheat arp_turn

arp_cheat:arp_cheat.c
	$(CC) arp_cheat.c -I$(INCLUDE) -L$(LIB) -o arp_cheat

arp_turn:arp_turn.c
	$(CC) arp_turn.c -I$(INCLUDE) -L$(LIB) -o arp_turn

pack: clean
	#nothing

clean:
	rm -f *.o arp_cheat arp_turn
