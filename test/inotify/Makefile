
CC=gcc
LDFLAG= -lpthread -lm
LDFLAG+= -L../../wf_lib/include/ -lwf
LDFLAG+= -L../../ghttp_lib/include/ -lghttp

CFLAG= -I../../wf_lib/include/
CFLAG= -I../../ghttp_lib/include/

TAG=inotify
all: $(TAG)

$(TAG): $(TAG).c
	$(CC) -g $(TAG).c $(CFLAG) $(LDFLAG) -o $@

pack: clean
	#nothing

clean:
	rm -f *.o $(TAG)
