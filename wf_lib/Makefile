
MAKELIB=ar
CC=cc
RM=rm

TARGET=libwf
#OBJ = ac_timer.o cJSON.o [libpx_thread.o pal_time.o] wf_bit.o \
	wf_char.o [wf_hacker.o] wf_ipc.o wf_kv.o wf_log.o wf_memory.o \
	wf_misc.o wf_net.o wf_threadpool.o wf_tree.o wf_param.o \
	strnormalize.o md5.o wf_base64.o
OBJ = ac_timer.o cJSON.o wf_bit.o wf_char.o wf_ipc.o wf_kv.o \
	wf_log.o wf_memory.o wf_misc.o wf_net.o wf_threadpool.o wf_tree.o \
	wf_param.o strnormalize.o md5.o wf_base64.o

all: $(TARGET).a $(TARGET).so

$(TARGET).a: $(OBJ)
	$(MAKELIB) -rv $@ $^
	cp -f $(TARGET).a include/
$(TARGET).so: $(OBJ)
	$(CC) -o $@ -fPIC -shared $^
#	cp -f $(TARGET).so include/
%.o: %.c
	$(CC) -c -Iinclude/ $< -o $@

pack: clean
	zip -qr $(TARGET).zip ./

clean:
	$(RM) -f *.o $(TARGET).a $(TARGET).so
