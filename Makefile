# Makefile for netprobe project

OBJS = main.o handle_packet.o flow.o

OUTDIR = bin
OUT = $(OUTDIR)/netprobe

CC = gcc
CFLAGS += -Wall -std=gnu11

LDFLAGS += -lpcap -lpthread -lcurl

ifdef DEBUG
	CFLAGS += -g -O0 -fsanitize=address -fno-omit-frame-pointer -DDEBUG
else
	CFLAGS += -O3
endif

all: build

build:	$(OBJS)
	mkdir -p bin/
	$(CC) $(CFLAGS) $(OBJS) -o $(OUT) $(LDFLAGS)
	
clean:
	rm -rf $(OBJS) $(OUTDIR)