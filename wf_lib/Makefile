
MAKELIB=ar
CC=cc
RM=rm

TARGET=libwf.a
#OBJ = ac_timer.o cJSON.o cJSON_Direct.o [libpx_thread.o pal_time.o] wf_bit.o \
	wf_char.o [wf_hacker.o] wf_ipc.o wf_kv.o wf_log.o wf_memory.o wf_misc.o  \
	wf_net.o wf_threadpool.o wf_tree.o wf_param.o strnormalize.o md5.o
OBJ = ac_timer.o cJSON.o cJSON_Direct.o wf_bit.o wf_char.o wf_ipc.o wf_kv.o \
	wf_log.o wf_memory.o wf_misc.o wf_net.o wf_threadpool.o wf_tree.o \
	wf_param.o strnormalize.o md5.o

all: $(TARGET)

$(TARGET): $(OBJ)
	$(MAKELIB) -rv $(TARGET) $(OBJ)
	cp -f $(TARGET) include/
%.o: %.c
	$(CC) -c -Iinclude/ $< -o $@

pack:
	$(RM) -f *.o
	#$(RM) -r testlog
	zip -qr $(TARGET).zip ./

clean:
	$(RM) -f *.o $(TARGET)
