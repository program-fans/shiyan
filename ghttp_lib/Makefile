
MAKELIB=ar
CC=cc
RM=rm

TARGET=libghttp.a
OBJ = ghttp.o http_base64.o http_date.o http_hdrs.o http_req.o http_resp.o \
	http_trans.o http_uri.o

all: $(TARGET)

$(TARGET): $(OBJ)
	$(MAKELIB) -rv $(TARGET) $(OBJ)
	cp -f $(TARGET) include/
%.o: %.c
	$(CC) -c -Iinclude/ $< -o $@

pack:
	$(RM) -f *.o
	zip -qr $(TARGET).zip ./

clean:
	$(RM) -f *.o $(TARGET)

