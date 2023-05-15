# Makefile for k5emulator

CC=gcc
COPTS=-g

default: k5emulator

k5emulator: k5emulator.c
	$(CC) $(COPTS) k5emulator.c -o k5emulator

clean:
	rm k5eulator
