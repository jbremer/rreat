CC = gcc
CFLAGS = -Wall -pedantic -O2 -std=c99
LIBS = -lpsapi

all: rreat.o

rreat.o: rreat.c config.h
	$(CC) $(CFLAGS) -c $^

%.exe: %.c rreat.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

test: test-child-detour.exe test-parent-detour.exe test-child-syshook.exe \
		test-parent-syshook.exe
	test-parent-detour.exe test-child-detour.exe
	test-parent-syshook.exe test-child-syshook.exe

poc:
	tar cf usch-poc.tar rreat.c rreat.h config.h usch-poc/child.c \
		usch-poc/parent.c usch-poc/child.exe usch-poc/parent.exe \
		usch-poc/Makefile Makefile
