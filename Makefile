CC = gcc
CCFLAGS = -Wall -ggdb
CFLAGS = -Wall -O2 -ggdb
LIBS = -lpcap
OBJS = main.o log.o
SRCS = ${OBJS:.o=.c}
TARGET = siphon

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CCFLAGS) -o $(TARGET) $(OBJS) $(LIBS)

clean:
	rm -f $(OBJS) *~ *.core core siphon
