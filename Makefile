CC = gcc
CFLAGS = -Wall -pedantic -O2 -std=c99
LIBS = -lpsapi

all: rreat.o

rreat.o: rreat.c
	$(CC) $(CFLAGS) -c $^

%.exe: %.c rreat.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

test: test-child.exe test-parent.exe
	test-parent.exe test-child.exe
