CC = gcc
CFLAGS = -Wall -pedantic -O2 -std=c99
LIBS = -lpsapi

all: rreat.o

rreat.o: rreat.c
	$(CC) $(CFLAGS) -c $^
