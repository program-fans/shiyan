
CC=gcc
LIB=../wf_lib/lib/libwf.a -lpthread
INCLUDE=-I../wf_lib/include/

all:arp_cheat arp_turn

arp_cheat:arp_cheat.c
	$(CC) arp_cheat.c $(INCLUDE) $(LIB) -o arp_cheat

arp_turn:arp_turn.c
	$(CC) arp_turn.c $(INCLUDE) $(LIB) -o arp_turn

clean:
	rm -f *.o arp_cheat arp_turn
