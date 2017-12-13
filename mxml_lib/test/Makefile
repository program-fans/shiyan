
MAKELIB=ar
CC=cc
RM=rm

src=$(wildcard *.c)
obj=$(src:.c=.o)
TARGET=testmxml

all: $(TARGET)

$(TARGET): $(src)
	$(CC) $^ -o $@ -I../include/ -L../lib/ -lmxml -lpthread

test:
	./$(TARGET) test.xml out.xml

pack: clean
	#nothing

clean:
	$(RM) -f *.o $(TARGET) *.xmlfd out.xml

