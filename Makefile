# Makefile for netprobe project

OBJS = main.o handle_packet.o flow.o
OUT = bin/netprobe

CC = gcc
CFLAGS += -Wall -std=gnu11

LDFLAGS += -lpcap -lpthread -lcurl

#DEBUG = 1

ifdef DEBUG
	CFLAGS += -g -O0 -Q -v
else
	CFLAGS += -O3
endif

all: build

build:	$(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(OUT) $(LDFLAGS)
	
clean:
	rm -rf $(OBJS) $(OUT)