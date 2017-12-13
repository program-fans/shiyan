
CC=gcc
RM=rm

CFLAGS= -Wall
CFLAGS+= -I../wf_lib/include/
CFLAGS+= -I../ghttp_lib/include/

LDFLAGS= -lpthread -lm
LDFLAGS+= ../wf_lib/lib/libwf.a

SOURCES = $(wildcard *.c)
OBJS = $(patsubst %.c,%.o,$(SOURCES))

TAG=netscan

.PHONY: $(TAG)

$(TAG):$(OBJS)
	$(CC) $^ $(LDFLAGS) -o $@

#TCPSCAN=tcpscan
#UDPSCAN=udpscan
#ICMPSCAN=icmpscan
#SSDPSCAN=ssdpscan

#all:$(TCPSCAN) $(UDPSCAN) $(ICMPSCAN) $(SSDPSCAN)

#$(TCPSCAN):tcpscan.o net_packet.o netscan.o
#	$(CC) $^ $(LDFLAGS) -o $@

#$(UDPSCAN):udpscan.o net_packet.o netscan.o
#	$(CC) $^ $(LDFLAGS) -o $@

#$(ICMPSCAN):icmpscan.o net_packet.o netscan.o
#	$(CC) $^ $(LDFLAGS) -o $@

#$(SSDPSCAN):ssdpscan.o
#	$(CC) $^ $(LDFLAGS) -o $@

%.o:%.c
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	$(RM) -f *.o $(TAG)
#	$(RM) -f *.o $(TCPSCAN) $(UDPSCAN) $(ICMPSCAN) $(SSDPSCAN)
